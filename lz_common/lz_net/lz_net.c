/*
 * Copyright(c) 2021 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <string.h>

#include "lz_config.h"
#include "lz_error.h"
#include "lz_common.h"
#include "lzport_debug_output.h"
#include "lzport_memory.h"
#include "lzport_net.h"
#include "lzport_gpio.h"
#if (1 == FREERTOS_AVAILABLE)
#include "lzport_delay.h"
#else
#include "lzport_systick_delay.h"
#endif
#include "lz_flash_handler.h"
#include "lz_net.h"
#include "sha256.h"
#include "ecdsa.h"
#include "lz_awdt_handler.h"
#include "lz_msg_decode.h"
#include "lz_msg_encode.h"
#include "lz_msg_frame.h"
#include "../../lz_demo_app/user_input.h"

#define TIMEOUT_SOCKET_OPEN_MS 5000
#define TIMEOUT_SOCKET_CLOSE_MS 5000
#define TIMEOUT_RECEIVE_MS 20000
#define TIMEOUT_TCP_MS 10000
#define CONNECT_RETRIES 3

static LZ_RESULT network_send(const uint8_t *request, uint32_t request_size);

static enum lz_msg_update_type to_lz_msg_update_type(hdr_type_t type);

static LZ_RESULT lz_flash_staging_element(const uint8_t *buf, uint32_t buf_size,
										  uint32_t total_size, uint32_t pending);

static LZ_RESULT flash_staging_header(hdr_type_t type, const uint8_t *msg, uint32_t msg_len,
									  uint32_t total_bytes, uint32_t *pending_bytes,
									  const uint8_t nonce[LEN_NONCE]);

static LZ_RESULT flash_staging_chunk(const uint8_t *chunk, size_t chunk_len, uint32_t total_bytes,
									 uint32_t *pending_bytes);

static LZ_RESULT receive_update_payload(hdr_type_t type, const uint8_t *msg, size_t msg_len,
										unsigned total_payload_bytes,
										const uint8_t nonce[LEN_NONCE]);

LZ_RESULT lz_net_init(void)
{
	uint8_t ipAddr[4] = { 0 };
	uint8_t macAddr[6] = { 0 };
	NET_RESULT result = LZ_ERROR;
	for (uint8_t i = 0; i < CONNECT_RETRIES; i++) {
		INFO("Connecting to '%s'\n", lz_data_store.config_data.nw_info.wifi_ssid);

		result =
			lzport_net_init(ipAddr, macAddr, (char *)lz_data_store.config_data.nw_info.wifi_ssid,
							(char *)lz_data_store.config_data.nw_info.wifi_pwd);
		if (result != NET_SUCCESS) {
			WARN("Failed to connect. Error Code = %x\n", result);
			INFO("Waiting for 1s..\n");
			lzport_delay(1000);
			INFO("Resetting the wifi module\n");
			if (lzport_net_reset() != NET_SUCCESS) {
				ERROR("Failed to reset ESP8266\n");
				continue;
			}
			INFO("Resetted ESP8266. Waiting for 5s..\n");
			lzport_delay(5000);
		} else {
			INFO("Successfully connected to '%s'\n", lz_data_store.config_data.nw_info.wifi_ssid);
			INFO("IP: %d.%d.%d.%d,  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ipAddr[0], ipAddr[1],
				 ipAddr[2], ipAddr[3], macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4],
				 macAddr[5]);
			return LZ_SUCCESS;
		}
	}

	ERROR("Failed to connect to WIFI\n");

	return LZ_ERROR_NET;
}

LZ_RESULT lz_net_open(void)
{
	INFO("Opening socket to port %d\n", lz_data_store.config_data.nw_info.server_port);

	const char *ip_addr = (char *)lz_data_store.config_data.nw_info.server_ip_addr;
	uint32_t port = lz_data_store.config_data.nw_info.server_port;

	if (lzport_socket_open(0, ip_addr, port, TIMEOUT_SOCKET_OPEN_MS) != NET_SUCCESS) {
		WARN("Failed to open socket\n");
		return LZ_ERROR;
	}

	INFO("Successfully opened socket to port %d\n", lz_data_store.config_data.nw_info.server_port);

	return LZ_SUCCESS;
}

LZ_RESULT lz_net_close(void)
{
	VERB("INFO: NET - Closing socket\n");

	if (lzport_socket_close(0, TIMEOUT_SOCKET_CLOSE_MS) != NET_SUCCESS) {
		WARN("Failed to close socket\n");
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

LZ_RESULT lz_net_close_reboot(void)
{
	INFO("Waiting for 2s before closing connection");
	lzport_delay(2000);
	lz_net_close();

	INFO("Waiting for 1s before rebooting");
	lzport_delay(1000);
	NVIC_SystemReset();
}

static LZ_RESULT network_receive_cb(struct lz_msg_istream *stream, uint8_t *buf, size_t buf_len)
{
	uint32_t received_bytes;
	if (lzport_socket_receive(0, buf, buf_len, TIMEOUT_RECEIVE_MS, &received_bytes) !=
		NET_SUCCESS) {
		ERROR("Timeout during socker receive\n");
		return LZ_ERROR_NET;
	}

	if (buf_len != received_bytes) {
		ERROR("Received %d bytes but expected %d bytes\n", received_bytes, buf_len);
		return LZ_ERROR_NET;
	}

	return LZ_SUCCESS;
}

LZ_RESULT lz_net_send_data(struct lz_net_sensor_data sensor_data)
{
	INFO("Sending sensor data to hub..\n");

	uint8_t uuid[LEN_UUID_V4_BIN];
	lz_get_uuid(uuid);

	const struct lz_msg_context context = {
		.uuid = uuid,
		.nonce = (uint8_t *)lz_next_nonce(),
	};

	unsigned buflen;
	if (lz_msg_get_length_sensor_data(&context, &buflen) != LZ_SUCCESS) {
		ERROR("Failed to get length protobuf message\n");
		return LZ_ERROR;
	}

	uint8_t buffer[buflen];
	size_t msg_len;

	if (lz_msg_encode_sensor_data(&context, buffer, &msg_len, sensor_data.index,
								  sensor_data.temperature, sensor_data.humidity) != LZ_SUCCESS) {
		ERROR("Failed to encode protobuf message\n");
		return LZ_ERROR;
	}

	if (network_send(buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to send data via network\n");
		return LZ_ERROR_NET;
	}

	struct lz_msg_istream stream = {
		.callback = network_receive_cb,
		.arg = NULL,
	};

	if (lz_msg_frame_read_size(&stream, &msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message size\n");
		return LZ_ERROR_NET;
	}

	uint8_t response_buffer[msg_len];
	if (lz_msg_frame_read_to_buffer(&stream, response_buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message to buffer\n");
		return LZ_ERROR_NET;
	}

	if (lz_msg_decode_sensor_data(response_buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to decode sensor data response\n");
		return LZ_ERROR;
	}

	INFO("Hub answered with ACK\n");
	return LZ_SUCCESS;
}

LZ_RESULT lz_net_send_alias_id_cert(void)
{
	LZ_RESULT result = LZ_SUCCESS;

	unsigned cert_len = lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_ALIASID].size;
	const uint8_t *cert =
		(uint8_t *)&lz_img_cert_store
			.certBag[lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_ALIASID].start];

	uint8_t uuid[LEN_UUID_V4_BIN];
	lz_get_uuid(uuid);

	struct lz_msg_context context = {
		.uuid = uuid,
		.nonce = NULL,
	};

	unsigned buflen;
	result = lz_msg_get_length_alias_id(&context, &buflen, cert, cert_len);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to get length protobuf message\n");
		return result;
	}

	uint8_t buffer[buflen];
	size_t msg_len;

	result = lz_msg_encode_alias_id(&context, buffer, &msg_len, cert, cert_len);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to encode protobuf message\n");
		return result;
	}

	if (network_send(buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to send AliasID via network\n");
		return LZ_ERROR_NET;
	}

	struct lz_msg_istream stream = {
		.callback = network_receive_cb,
		.arg = NULL,
	};

	if (lz_msg_frame_read_size(&stream, &msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message size\n");
		return LZ_ERROR_NET;
	}

	uint8_t response_buffer[msg_len];
	if (lz_msg_frame_read_to_buffer(&stream, response_buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message to buffer\n");
		return LZ_ERROR_NET;
	}

	if (lz_msg_decode_alias_id(response_buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to receive and decode alias ID response\n");
		return LZ_ERROR;
	}
	return result;
}

LZ_RESULT lz_net_refresh_boot_ticket(void)
{
	LZ_RESULT result = LZ_SUCCESS;

	uint8_t uuid[LEN_UUID_V4_BIN];
	lz_get_uuid(uuid);

	const struct lz_msg_context context = {
		.uuid = uuid,
		.nonce = (uint8_t *)lz_next_nonce(),
	};

	unsigned buflen;
	result = lz_msg_get_length_refresh_boot_ticket(&context, &buflen);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to get length protobuf message\n");
		return result;
	}

	uint8_t buffer[buflen];
	size_t msg_len;

	result = lz_msg_encode_refresh_boot_ticket(&context, buffer, &msg_len);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to encode protobuf message\n");
		return result;
	}

	if (network_send(buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to send boot ticket via network\n");
		return LZ_ERROR_NET;
	}

	struct lz_msg_istream stream = {
		.callback = network_receive_cb,
		.arg = NULL,
	};

	if (lz_msg_frame_read_size(&stream, &msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message size\n");
		return LZ_ERROR_NET;
	}

	uint8_t response_buffer[msg_len];
	if (lz_msg_frame_read_to_buffer(&stream, response_buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message to buffer\n");
		return LZ_ERROR_NET;
	}

	INFO("Received boot ticket from backend\n");

	// We don't need the decoded message here. We will directly write the raw
	// message to the staging area. Yet, we will decode the message here to be
	// able to detect possible errors as early as possible.
	uint8_t nonce[LEN_NONCE];
	if (lz_msg_decode_refresh_boot_ticket(response_buffer, msg_len, nonce) != LZ_SUCCESS) {
		ERROR("Failed to decode boot ticket response\n");
		return LZ_ERROR;
	}

	lz_staging_hdr_t hdr;
	hdr.payload_size = msg_len;
	hdr.magic = LZ_MAGIC;
	hdr.type = BOOT_TICKET;
	hdr.msg_size = msg_len;
	memcpy(hdr.nonce, nonce, LEN_NONCE);

	if (lz_flash_staging_element((uint8_t *)&hdr, sizeof(hdr), sizeof(hdr) + msg_len,
								 sizeof(hdr) + msg_len) != LZ_SUCCESS) {
		ERROR("Failed to flash header.\n");
		return LZ_ERROR;
	}

	if (lz_flash_staging_element(response_buffer, msg_len, sizeof(hdr) + msg_len, msg_len) !=
		LZ_SUCCESS) {
		ERROR("Failed to flash payload.\n");
		return LZ_ERROR;
	}

	INFO("Wrote boot ticket to staging area\n");
	return LZ_SUCCESS;
}

LZ_RESULT lz_net_refresh_awdt(uint32_t requested_time_ms)
{
	LZ_RESULT result = LZ_SUCCESS;

	INFO("Generating ticket request with nonce..\n");

	uint8_t nonce[LEN_NONCE];
	if (lz_awdt_get_nonce_nse(nonce) != LZ_SUCCESS) {
		ERROR("Failed to get nonce for AWDT refresh message\n");
		return LZ_ERROR;
	}

	uint8_t uuid[LEN_UUID_V4_BIN];
	lz_get_uuid(uuid);

	struct lz_msg_context context = {
		.uuid = uuid,
		.nonce = nonce,
	};

	unsigned buflen;
	result = lz_msg_get_length_refresh_awdt(&context, &buflen);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to get length protobuf message\n");
		return result;
	}

	uint8_t buffer[buflen];
	size_t msg_len;

	result = lz_msg_encode_refresh_awdt(&context, buffer, &msg_len, requested_time_ms);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to encode protobuf message\n");
		return result;
	}

	if (network_send(buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to send AWDT ticket via network\n");
		return LZ_ERROR_NET;
	}

	struct lz_msg_istream stream = {
		.callback = network_receive_cb,
		.arg = NULL,
	};

	if (lz_msg_frame_read_size(&stream, &msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message size\n");
		return LZ_ERROR_NET;
	}

	uint8_t response_buffer[msg_len];
	if (lz_msg_frame_read_to_buffer(&stream, response_buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message to buffer\n");
		return LZ_ERROR_NET;
	}

	INFO("Received ticket from backend for AWDT deferral\n");
	INFO("Trying to restart AWDT..\n");

	if (lz_awdt_put_ticket_nse(response_buffer, msg_len) != LZ_SUCCESS) {
		WARN("Could not restart AWDT\n");
		return LZ_ERROR;
	}

	INFO("Successfully restarted AWDT\n");
	return LZ_SUCCESS;
}

static void convert_version_info(struct lz_net_version_info *dest, struct lz_msg_version_info *src)
{
	assert(sizeof(dest->name) == sizeof(src->name));
	assert(sizeof(dest->newest_version) == sizeof(src->newest_version));

	memcpy(dest->name, src->name, sizeof(src->name));

	memcpy(dest->newest_version, src->newest_version, sizeof(src->newest_version));

	dest->issue_time = src->issue_time;
}

LZ_RESULT lz_net_check_for_update(hdr_type_t update_types[], unsigned num_update_types,
								  struct lz_net_check_for_update_result *net_response)
{
	LZ_RESULT result = LZ_ERROR;
	enum lz_msg_update_type msg_types[LZ_NET_MAX_COMPONENTS];
	struct lz_msg_check_for_update_response msg_response;

	INFO("Sending \"check for update\" request to backend..\n");

	uint8_t uuid[LEN_UUID_V4_BIN];
	lz_get_uuid(uuid);

	struct lz_msg_context context = {
		.uuid = uuid,
		.nonce = (uint8_t *)lz_next_nonce(),
	};

	for (int i = 0; i < num_update_types; i++)
		msg_types[i] = to_lz_msg_update_type(update_types[i]);

	unsigned buflen;
	result = lz_msg_get_length_check_for_update(&context, &buflen, msg_types, num_update_types);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to get length protobuf message\n");
		return result;
	}

	uint8_t buffer[buflen];
	size_t msg_len;

	result =
		lz_msg_encode_check_for_update(&context, buffer, &msg_len, msg_types, num_update_types);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to encode protobuf message\n");
		return result;
	}

	if (network_send(buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to send update check via network\n");
		return LZ_ERROR_NET;
	}

	struct lz_msg_istream stream = {
		.callback = network_receive_cb,
		.arg = NULL,
	};

	if (lz_msg_frame_read_size(&stream, &msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message size\n");
		return LZ_ERROR_NET;
	}

	uint8_t response_buffer[msg_len];
	if (lz_msg_frame_read_to_buffer(&stream, response_buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message to buffer\n");
		return LZ_ERROR_NET;
	}

	INFO("Received \"check for update\" response from backend\n");

	if (lz_msg_decode_check_for_update(response_buffer, msg_len, &msg_response) != LZ_SUCCESS) {
		ERROR("Failed to decode \"check for update\" response\n");
		return LZ_ERROR;
	}

	if (msg_response.num_components != num_update_types) {
		ERROR("Received different number of version infos than in request\n");
		return LZ_ERROR;
	}

	if (memcmp(context.nonce, msg_response.nonce, LEN_NONCE)) {
		ERROR("Nonce of response message does not match with request\n");
		return LZ_ERROR;
	}

	for (int i = 0; i < num_update_types; i++) {
		convert_version_info(&net_response->components[i], &msg_response.components[i]);
	}
	return LZ_SUCCESS;
}

LZ_RESULT lz_net_fw_update(hdr_type_t update_type)
{
	LZ_RESULT result = LZ_SUCCESS;

	INFO("Generating update request..\n");

	uint8_t uuid[LEN_UUID_V4_BIN];
	lz_get_uuid(uuid);

	const struct lz_msg_context context = {
		.uuid = uuid,
		.nonce = (uint8_t *)lz_next_nonce(),
	};

	unsigned buflen;
	enum lz_msg_update_type type = to_lz_msg_update_type(update_type);
	result = lz_msg_get_length_update(&context, &buflen, type);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to get length protobuf message\n");
		return result;
	}

	uint8_t buffer[buflen];
	size_t msg_len;

	result = lz_msg_encode_update(&context, buffer, &msg_len, type);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to encode protobuf message\n");
		return result;
	}

	INFO("Request %s update from server..\n", HDR_TYPE_STRING[update_type]);

	if (network_send(buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to send update request via network\n");
		return LZ_ERROR_NET;
	}

	struct lz_msg_istream stream = {
		.callback = network_receive_cb,
		.arg = NULL,
	};

	if (lz_msg_frame_read_size(&stream, &msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message size\n");
		return LZ_ERROR_NET;
	}

	uint8_t response_buffer[msg_len];
	if (lz_msg_frame_read_to_buffer(&stream, response_buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message to buffer\n");
		return LZ_ERROR_NET;
	}

	INFO("Received update response from hub\n");

	unsigned payload_len;
	uint8_t nonce[LEN_NONCE];
	if (lz_msg_decode_update(response_buffer, msg_len, &payload_len, nonce) != LZ_SUCCESS) {
		ERROR("Failed to decode update response message\n");
		return LZ_ERROR;
	}

	INFO("Decoded response: payload size %d\n", payload_len);
	INFO("Receiving the update (this may take a while)\n");

	result = receive_update_payload(update_type, response_buffer, msg_len, payload_len, nonce);
	return result;
}

LZ_RESULT lz_net_request_user_input(void)
{
	LZ_RESULT result = LZ_SUCCESS;

	INFO("Generating user input request..\n");

	uint8_t uuid[LEN_UUID_V4_BIN];
	lz_get_uuid(uuid);

	struct lz_msg_context context = {
		.uuid = uuid,
		.nonce = (uint8_t *)lz_next_nonce(),
	};

	unsigned buflen;
	result = lz_msg_get_length_request_user_input(&context, &buflen);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to get length protobuf message\n");
		return result;
	}

	uint8_t buffer[buflen];
	size_t msg_len;

	result = lz_msg_encode_request_user_input(&context, buffer, &msg_len);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to encode protobuf message\n");
		return result;
	}

	if (network_send(buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to send user input request via network\n");
		return LZ_ERROR_NET;
	}

	struct lz_msg_istream stream = {
		.callback = network_receive_cb,
		.arg = NULL,
	};

	if (lz_msg_frame_read_size(&stream, &msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message size\n");
		return LZ_ERROR_NET;
	}

	uint8_t response_buffer[msg_len];
	if (lz_msg_frame_read_to_buffer(&stream, response_buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message to buffer\n");
		return LZ_ERROR_NET;
	}

	uint8_t response_buf[50];
	uint32_t response_len = sizeof(response_buf);
	bool available;
	if (lz_msg_decode_user_input(response_buffer, msg_len, response_buf, &response_len,
								 &available) != LZ_SUCCESS) {
		ERROR("Failed to receive and decode user input response\n");
		return LZ_ERROR;
	}

	process_user_input(response_buf, response_len, available);

	return result;
}

static enum lz_msg_update_type to_lz_msg_update_type(hdr_type_t type)
{
	switch (type) {
	case APP_UPDATE:
		return LZ_MSG_UPDATE_TYPE_APP;
	case LZ_UDOWNLOADER_UPDATE:
		return LZ_MSG_UPDATE_TYPE_UDOWNLOADER;
	case LZ_CPATCHER_UPDATE:
		return LZ_MSG_UPDATE_TYPE_CPATCHER;
	case LZ_CORE_UPDATE:
		return LZ_MSG_UPDATE_TYPE_CORE;
	case CONFIG_UPDATE:
		return LZ_MSG_UPDATE_TYPE_CONFIG;
	default:
		WARN("Invalid update type. Assuming app update..\n");
		return LZ_MSG_UPDATE_TYPE_APP;
	}
}

LZ_RESULT lz_net_reassociate_device(uint8_t *dev_uuid, uint8_t *dev_auth, uint8_t *device_id_csr,
									uint32_t device_id_csr_size)
{
	LZ_RESULT result = LZ_SUCCESS;

	INFO("Generating reassociation request..\n");

	uint8_t uuid[LEN_UUID_V4_BIN];
	lz_get_uuid(uuid);

	const struct lz_msg_context context = {
		.uuid = uuid,
		.nonce = (uint8_t *)lz_next_nonce(),
	};

	struct lz_msg_reassoc_info reassoc_info = {
		.uuid = uuid,
		.uuid_len = LEN_UUID_V4_BIN,
		.auth = dev_auth,
		.auth_len = SHA256_DIGEST_LENGTH,
		.dev_id_csr = device_id_csr,
		.dev_id_csr_len = device_id_csr_size,
	};

	unsigned buflen;
	result = lz_msg_get_length_reassoc(&context, &buflen, reassoc_info);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to get length protobuf message\n");
		return result;
	}

	uint8_t buffer[buflen];
	size_t msg_len;

	result = lz_msg_encode_reassoc(&context, buffer, &msg_len, reassoc_info);
	if (result != LZ_SUCCESS) {
		ERROR("Failed to encode protobuf message\n");
		return result;
	}

	if (network_send(buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to send device re-association via network\n");
		return LZ_ERROR_NET;
	}

	struct lz_msg_istream stream = {
		.callback = network_receive_cb,
		.arg = NULL,
	};

	if (lz_msg_frame_read_size(&stream, &msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message size\n");
		return LZ_ERROR_NET;
	}

	uint8_t response_buffer[msg_len];
	if (lz_msg_frame_read_to_buffer(&stream, response_buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message to buffer\n");
		return LZ_ERROR_NET;
	}

	INFO("Received reassociation response from hub\n");

	// Hub will answer with an update response to our request
	unsigned payload_len;
	uint8_t nonce[LEN_NONCE];
	if (lz_msg_decode_reassoc(response_buffer, msg_len, &payload_len, nonce) != LZ_SUCCESS) {
		ERROR("Failed to decode update response message\n");
		return LZ_ERROR;
	}

	INFO("Decoded response: payload size %d\n", payload_len);
	INFO("Receiving the update (this may take a while)\n");

	result =
		receive_update_payload(DEVICE_ID_REASSOC_RES, response_buffer, msg_len, payload_len, nonce);
	return result;
}

static LZ_RESULT network_send(const uint8_t *request, uint32_t request_size)
{
	NET_RESULT result =
		lzport_socket_send(0, (unsigned char *)request, request_size, TIMEOUT_TCP_MS);
	if (result != LZ_SUCCESS) {
		ERROR("WARN: Failed to send to socket. Error code %x\n", result);
		return LZ_ERROR_NET;
	}
	return LZ_SUCCESS;
}

uint8_t buf[4 * 1460] = { 0 }; // TODO magic number -> maximum of IPD receive

static LZ_RESULT receive_update_payload(hdr_type_t type, const uint8_t *msg, size_t msg_len,
										unsigned total_payload_bytes,
										const uint8_t nonce[LEN_NONCE])
{
	unsigned previous_progress = 0;
	uint32_t total_received_bytes = 0;

	uint32_t total_bytes = sizeof(lz_staging_hdr_t) + msg_len + total_payload_bytes;
	uint32_t pending_bytes = total_bytes;
	if (flash_staging_header(type, msg, msg_len, total_bytes, &pending_bytes, nonce) != LZ_SUCCESS)
		return LZ_ERROR;

	while (total_received_bytes < total_payload_bytes) {
		VERB("INFO: Receiving FW update chunk\n");

		uint32_t received_bytes;
		if (lzport_socket_receive(0, buf, sizeof(buf), TIMEOUT_RECEIVE_MS, &received_bytes) !=
			LZ_SUCCESS) {
			ERROR("Failed to receive from socket during firmware update\n");
			return LZ_ERROR;
		}
		total_received_bytes += received_bytes;

		if (flash_staging_chunk(buf, received_bytes, total_bytes, &pending_bytes) != LZ_SUCCESS)
			return LZ_ERROR;

		VERB("INFO: Received FW chunk (received: %d, pending: %d, total size: %d)\n",
			 total_received_bytes, total_payload_bytes - total_received_bytes, total_payload_bytes);

		// Indicate progress
		uint32_t progress = (total_received_bytes * 100) / total_payload_bytes;
		if (progress >= previous_progress + 10) {
			INFO("%d%%\n", progress);
			previous_progress = progress;
		}
	}

	INFO("Downloading firmware update successful\n");
	return LZ_SUCCESS;
}

/**
 * Find the next free slot in the staging area and return its address
 *
 * @param staging_elem_slot The address of the next free slot that is returned
 * @param size_req The size of the requested slot including the header
 * @return LZ_SUCCESS, if a slot was found, otherwise LZ_ERROR
 */
static LZ_RESULT lz_get_next_staging_slot(uint8_t **staging_slot, uint32_t size_req)
{
	uint32_t staging_area_size = sizeof(lz_staging_area.content);
	uint32_t cursor = 0;
	LZ_RESULT result = LZ_ERROR;

	while (cursor < staging_area_size) {
		lz_staging_hdr_t *staging_elem_hdr =
			(lz_staging_hdr_t *)(((uint32_t)&lz_staging_area.content) + cursor);

		// If the header is invalid or there is no header at all, we can override it
		if (!(staging_elem_hdr->magic == LZ_MAGIC) || (staging_elem_hdr->payload_size == 0) ||
			memcmp((void *)staging_elem_hdr->nonce, (void *)lz_img_boot_params.info.next_nonce,
				   sizeof(staging_elem_hdr->nonce))) {
			// Check if the element fits into the staging area
			if (size_req < (staging_area_size - cursor)) {
				*staging_slot = (uint8_t *)staging_elem_hdr;
				VERB("Found staging element slot at location: 0x%x\n", staging_elem_hdr);

				result = LZ_SUCCESS;
				break;
			} else {
				result = LZ_ERROR;
				break;
			}
		}

		// Move cursor to next element
		cursor += (staging_elem_hdr->payload_size + sizeof(lz_staging_hdr_t));
	}

	// Staging area already filled, cannot find slot
	return result;
}

static LZ_RESULT lz_flash_staging_element(const uint8_t *buf, uint32_t buf_size,
										  uint32_t total_size, uint32_t pending)
{
	static uint8_t *start = NULL;
	LZ_RESULT result = LZ_ERROR;

	// Get next slot in staging area if a new firmware is to be flashed
	if (pending == total_size) {
		if (lz_get_next_staging_slot(&start, buf_size) != LZ_SUCCESS) {
			ERROR("Could not find a place on staging area.\n");
			return LZ_ERROR;
		}
	}

	VERB("Writing %d bytes (RAM Address 0x%x, total %d, pending %d) to flash address "
		 "0x%x\n",
		 buf_size, buf, total_size, pending, start);

	// Set RTS to pause UART sending as data cannot be received
	// while writing to flash, disable IRQs as they cannot be served as well
	lzport_gpio_set_rts(true);
	lzport_delay(10);
	__disable_irq();

	if (!(lz_flash_write_nse((void *)start, (void *)buf, buf_size))) {
		ERROR("Failed to write staging element to flash.\n");
		goto exit;
	}

	start += buf_size;
	result = LZ_SUCCESS;

exit:
	// Reset RTS to signal that sending is possible again
	// and re-enable interrupts
	__enable_irq();
	lzport_gpio_set_rts(false);
	return result;
}

static LZ_RESULT flash_staging_header(hdr_type_t type, const uint8_t *msg, uint32_t msg_len,
									  uint32_t total_bytes, uint32_t *pending_bytes,
									  const uint8_t nonce[LEN_NONCE])
{
	lz_staging_hdr_t header = { 0 };
	header.magic = LZ_MAGIC;
	header.type = type;
	header.payload_size = total_bytes - sizeof(lz_staging_hdr_t);
	header.msg_size = msg_len;
	memcpy(header.nonce, nonce, LEN_NONCE);

	if (lz_flash_staging_element((void *)&header, sizeof(header), total_bytes, *pending_bytes) !=
		LZ_SUCCESS) {
		ERROR("Failed to flash staging header\n");
		return LZ_ERROR;
	}

	*pending_bytes -= sizeof(header);

	if (lz_flash_staging_element(msg, msg_len, total_bytes, *pending_bytes) != LZ_SUCCESS) {
		ERROR("Failed to flash staging header\n");
		return LZ_ERROR;
	}

	*pending_bytes -= msg_len;
	return LZ_SUCCESS;
}

static LZ_RESULT flash_staging_chunk(const uint8_t *chunk, size_t chunk_len, uint32_t total_bytes,
									 uint32_t *pending_bytes)
{
	// Write data to flash
	if (lz_flash_staging_element((uint8_t *)chunk, chunk_len, total_bytes, *pending_bytes) !=
		LZ_SUCCESS) {
		ERROR("Failed to flash staging element\n");
		return LZ_ERROR;
	}

	*pending_bytes -= chunk_len;
	return LZ_SUCCESS;
}
