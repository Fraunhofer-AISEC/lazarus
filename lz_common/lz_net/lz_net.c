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

#include "stdint.h"

#include "lz_config.h"
#include "lz_common.h"
#include "lzport_debug_output.h"
#include "lzport_memory.h"
#include "lzport_net.h"
#include "lz_flash_handler.h"
#include "lz_net.h"
#include "lz_sha256.h"
#include "lz_ecdsa.h"
#include "lz_awdt_handler.h"

#define TIMEOUT_SOCKET_OPEN_MS 5000
#define TIMEOUT_RECEIVE_FW_MS 20000
#define TIMEOUT_TCP_MS 10000

// Currently the maximum size of an ESP packet
#define MAX_CERT_SIZE 1460

static LZ_RESULT lz_net_request(char *ip_addr, uint32_t port, const uint8_t *request,
								uint32_t request_size, uint8_t *response, uint32_t response_size);

static LZ_RESULT lz_net_update(hdr_type_t update_type, uint8_t *payload, uint32_t payload_size);

LZ_RESULT lz_net_init(void)
{
	uint8_t ipAddr[4] = { 0 };
	uint8_t macAddr[6] = { 0 };
	LZ_RESULT result = LZ_ERROR;
	for (uint8_t i = 0; i < 3; i++) {
		dbgprint(DBG_INFO, "INFO: Connecting to '%s'\n",
				 lz_data_store.config_data.nw_info.wifi_ssid);

		if (lzport_net_init(ipAddr, macAddr, (char *)lz_data_store.config_data.nw_info.wifi_ssid,
							(char *)lz_data_store.config_data.nw_info.wifi_pwd) != LZ_SUCCESS) {
			dbgprint(DBG_WARN, "WARN: Failed to connect. \n");
		} else {
			dbgprint(DBG_INFO, "INFO: Successfully connected to '%s'\n",
					 lz_data_store.config_data.nw_info.wifi_ssid);
			dbgprint(DBG_INFO, "INFO: IP: %d.%d.%d.%d,  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
					 ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3], macAddr[0], macAddr[1], macAddr[2],
					 macAddr[3], macAddr[4], macAddr[5]);
			result = LZ_SUCCESS;
			break;
		}
	}

	return result;
}

LZ_RESULT lz_net_send_data(uint8_t *data, uint32_t data_size)
{
	LZ_RESULT result = LZ_ERROR;
	dbgprint(DBG_INFO, "INFO: Sending data..\n");

	lz_auth_hdr_t element_request = { 0 };
	element_request.content.magic = LZ_MAGIC;
	element_request.content.payload_size = data_size;
	lz_get_uuid(element_request.content.uuid);
	element_request.content.type = SENSOR_DATA;
	memcpy((void *)element_request.content.nonce, (void *)lz_img_boot_params.info.next_nonce,
		   LEN_NONCE);

	// The response is just an ACK/NAK
	uint32_t response_payload;

	if (lz_request_auth_element(&element_request, data, &element_request,
								(uint8_t *)&response_payload, sizeof(uint32_t)) != LZ_SUCCESS) {
		dbgprint(DBG_WARN, "WARN: Failed to send data to backend\n");
		goto Exit;
	}

	dbgprint(DBG_INFO, "INFO: Server answered with %s\n",
			 (response_payload == TCP_CMD_ACK) ? "ACK" : "NAK");

	result = LZ_SUCCESS;

Exit:
	return result;
}

LZ_RESULT lz_net_send_alias_id_cert(void)
{
	LZ_RESULT result = LZ_ERROR;

	dbgprint(DBG_INFO, "INFO: Sending alias certificate to backend..\n");

	hdr_t alias_id_cert_hdr = { 0 };
	hdr_t response_hdr = { 0 };
	uint32_t response_payload;

	alias_id_cert_hdr.type = ALIAS_ID;
	alias_id_cert_hdr.payload_size =
		lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_ALIASID].size;
	lz_get_uuid(alias_id_cert_hdr.uuid);

	if (lz_request_element(
			&alias_id_cert_hdr,
			(uint8_t *)&lz_img_cert_store
				.certBag[lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_ALIASID].start],
			&response_hdr, (uint8_t *)&response_payload, sizeof(response_payload)) != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Failed to send AliasID certificate\n");
		goto exit;
	}

	// Check response
	if (TCP_CMD_ACK == response_payload) {
		dbgprint(DBG_INFO, "INFO: Successfully sent AliasID certificate\n");
	} else if (response_payload == TCP_CMD_NAK) {
		dbgprint(DBG_INFO, "INFO: Received response NAK. Server refused to update certificate\n",
				 response_payload);
		goto exit;
	} else {
		dbgprint(DBG_INFO, "INFO: Updating AliasID not successful. Received response %d\n",
				 response_payload);
		goto exit;
	}

	result = LZ_SUCCESS;

exit:
	return result;
}

LZ_RESULT lz_net_refresh_boot_ticket(void)
{
	LZ_RESULT result = LZ_ERROR;
	uint32_t size = sizeof(lz_auth_hdr_t) + sizeof(uint32_t);
	uint8_t data[size];

	dbgprint(DBG_INFO, "INFO: Generating boot ticket request..\n");

	uint32_t payload = LZ_MAGIC;
	lz_auth_hdr_t element_request = { 0 };
	element_request.content.magic = LZ_MAGIC;
	element_request.content.payload_size = sizeof(uint32_t);
	lz_get_uuid(element_request.content.uuid);
	element_request.content.type = BOOT_TICKET;
	memcpy((void *)element_request.content.nonce, (void *)lz_img_boot_params.info.next_nonce,
		   LEN_NONCE);

	if (lz_request_auth_element(&element_request, (uint8_t *)&payload, &element_request,
								(uint8_t *)&payload, sizeof(uint32_t)) != LZ_SUCCESS) {
		dbgprint(DBG_WARN, "WARN: Failed to retrieve boot ticket from backend\n");
		goto Exit;
	}

	dbgprint(DBG_INFO, "INFO: Received boot ticket from backend\n");

	memcpy((void *)data, &element_request, sizeof(lz_auth_hdr_t));
	memcpy((void *)(data + sizeof(lz_auth_hdr_t)), &payload, sizeof(uint32_t));

	if (lz_flash_staging_element(data, size, size, size) != LZ_SUCCESS) {
		goto Exit;
	}

	dbgprint(DBG_INFO, "INFO: Wrote ticket to staging area\n");
	result = LZ_SUCCESS;

Exit:
	return result;
}

LZ_RESULT lz_net_refresh_awdt(uint32_t requested_time_ms)
{
	LZ_RESULT result = LZ_ERROR;

	dbgprint(DBG_INFO, "INFO: Generating ticket request with nonce..\n");

	uint32_t time_ms = requested_time_ms;
	lz_auth_hdr_t element_request = { 0 };
	element_request.content.magic = LZ_MAGIC;
	element_request.content.payload_size = sizeof(uint32_t);
	lz_get_uuid(element_request.content.uuid);
	element_request.content.type = DEFERRAL_TICKET;
	if (lz_awdt_get_nonce_nse(element_request.content.nonce) != LZ_SUCCESS) {
		dbgprint(DBG_INFO, "ERROR: Failed to get nonce from AWDT\n");
		result = LZ_ERROR;
		goto exit;
	}

	if (lz_request_auth_element(&element_request, (uint8_t *)&time_ms, &element_request,
								(uint8_t *)&time_ms, sizeof(uint32_t)) != LZ_SUCCESS) {
		dbgprint(DBG_WARN, "WARN: Failed to retrieve boot ticket from backend\n");
		result = LZ_ERROR;
		goto exit;
	}

	dbgprint(DBG_INFO, "INFO: Received ticket from backend with deferral time %d\n", time_ms);
	dbgprint(DBG_INFO, "INFO: Trying to restart AWDT..\n");

	if (lz_awdt_put_ticket_nse(&element_request, time_ms) != LZ_SUCCESS) {
		dbgprint(DBG_WARN, "WARN: Could not restart AWDT\n");
		result = LZ_ERROR;
		goto exit;
	}

	dbgprint(DBG_INFO, "INFO: Successfully restarted AWDT with timeout %d\n", time_ms);
	result = LZ_SUCCESS;

exit:
	return result;
}

LZ_RESULT lz_net_fw_update(hdr_type_t update_type)
{
	// For now, just a dummy payload is sent as payload cannot be zero
	uint32_t payload = LZ_MAGIC;
	uint32_t payload_size = 0x4;

	return lz_net_update(update_type, (uint8_t *)&payload, payload_size);
}

LZ_RESULT lz_net_reassociate_device(uint8_t *dev_uuid, uint8_t *dev_auth, uint8_t *device_id_csr,
									uint32_t device_id_csr_size)
{
	// TODO scatter-list style handover of parameters to send function
	uint8_t buf[LEN_UUID_V4_BIN + SHA256_DIGEST_LENGTH + device_id_csr_size];
	memcpy((void *)buf, (void *)dev_uuid, LEN_UUID_V4_BIN);
	memcpy((void *)(buf + LEN_UUID_V4_BIN), (void *)dev_auth, SHA256_DIGEST_LENGTH);
	memcpy((void *)(buf + LEN_UUID_V4_BIN + SHA256_DIGEST_LENGTH), (void *)device_id_csr,
		   device_id_csr_size);

	return lz_net_update(DEVICE_ID_REASSOC_REQ, buf, sizeof(buf));
}

LZ_RESULT lz_request_element(hdr_t *request_hdr, uint8_t *request_payload, hdr_t *response_hdr,
							 uint8_t *response_payload, uint32_t response_payload_size)
{
	LZ_RESULT result = LZ_ERROR;

	// tcp buffer to send and receive: header + payload
	uint8_t tcp_buf[sizeof(hdr_t) + request_hdr->payload_size];
	memcpy((void *)tcp_buf, (void *)request_hdr, sizeof(hdr_t));
	memcpy((void *)(tcp_buf + sizeof(hdr_t)), (void *)request_payload, request_hdr->payload_size);

	uint8_t tcp_buf_response[sizeof(hdr_t) + response_payload_size];

	if (lz_net_request((char *)lz_data_store.config_data.nw_info.server_ip_addr,
					   lz_data_store.config_data.nw_info.server_port, tcp_buf, sizeof(tcp_buf),
					   tcp_buf_response, sizeof(tcp_buf_response)) != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Failed to receive data from network\n");
		result = LZ_ERROR;
		goto exit;
	}

	memcpy(response_hdr, tcp_buf_response, sizeof(hdr_t));

	if (response_payload_size < response_hdr->payload_size) {
		dbgprint(DBG_ERR, "ERROR: Specified response payload buffer too small\n");
		result = LZ_ERROR;
		goto exit;
	}

	memcpy(response_payload, tcp_buf_response + sizeof(hdr_t), response_hdr->payload_size);

	result = LZ_SUCCESS;

exit:
	return result;
}

/**
 * lazarus authenticated network request
 * @param element_request
 * @param payload
 * @return
 */
// TODO merge with fw_update function for generic tcp element request function for
// arbitrarily sized objects
LZ_RESULT lz_request_auth_element(lz_auth_hdr_t *request_hdr, uint8_t *request_payload,
								  lz_auth_hdr_t *response_hdr, uint8_t *response_payload,
								  uint32_t response_payload_size)
{
	LZ_RESULT result = LZ_ERROR;

	// tcp buffer to send TODO lz_net_request should take buffer list
	uint8_t tcp_buf[sizeof(lz_auth_hdr_t) + request_hdr->content.payload_size];

	// tcp buffer to receive TODO lz_net_request should take buffer list
	uint8_t tcp_buf_response[sizeof(lz_auth_hdr_t) + response_payload_size];

	dbgprint(DBG_INFO, "INFO: Signing request with AliasID..\n");

	// Hash the payload of the ticket
	if (lz_sha256(request_hdr->content.digest, request_payload,
				  request_hdr->content.payload_size) != 0) {
		dbgprint(DBG_WARN, "WARN: Failed to hash payload of ticket\n");
		result = LZ_ERROR;
		goto exit;
	}

	// Sign the request with the DeviceID private key
	lz_ecc_signature ecc_sig;

	int status =
		lz_ecdsa_sign_pem((void *)&request_hdr->content, sizeof(request_hdr->content),
						  (lz_ecc_priv_key_pem *)&lz_img_boot_params.info.alias_id_keypair_priv,
						  &ecc_sig);

	if (0 != status) {
		dbgprint(DBG_ERR, "ERROR: lz_ecdsa_sign_pem\n");
		result = LZ_ERROR;
		goto exit;
	}

	// Convert signature
	memcpy(&request_hdr->signature, &ecc_sig, sizeof(ecc_sig));

	dbgprint(DBG_INFO, "INFO: Sending request to backend..\n");

	// Send header + payload
	memcpy((void *)tcp_buf, (void *)request_hdr, sizeof(lz_auth_hdr_t));
	memcpy((void *)(tcp_buf + sizeof(lz_auth_hdr_t)), request_payload,
		   request_hdr->content.payload_size);

	// Timestamp 2 (falling edge) - begin network
#if (1 == LZ_DBG_TRACE_DEFERRAL_ACTIVE)
	lzport_gpio_toggle_trace();
#endif

	if (lz_net_request((char *)lz_data_store.config_data.nw_info.server_ip_addr,
					   lz_data_store.config_data.nw_info.server_port, tcp_buf, sizeof(tcp_buf),
					   tcp_buf_response, sizeof(tcp_buf_response)) != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Failed to send and receive data via TCP\n");
		result = LZ_ERROR;
		goto exit;
	}

	// Copy header and payload
	memcpy(response_hdr, tcp_buf_response, sizeof(lz_auth_hdr_t));
	// Received payload must be equally sized, create generic function for all payloads
	memcpy(response_payload, tcp_buf_response + sizeof(lz_auth_hdr_t),
		   response_hdr->content.payload_size);

	result = LZ_SUCCESS;

exit:
	return result;
}

static LZ_RESULT lz_net_request(char *ip_addr, uint32_t port, const uint8_t *request,
								uint32_t request_size, uint8_t *response, uint32_t response_size)
{
	LZ_RESULT result = LZ_ERROR;
	uint32_t received;
	if (lzport_socket_open(0, ip_addr, port, TIMEOUT_TCP_MS) != LZ_SUCCESS) {
		dbgprint(DBG_WARN, "WARN: Failed to open socket\n");
		result = LZ_ERROR;
		goto exit;
	}

	if (lzport_socket_send(0, (unsigned char *)request, request_size, TIMEOUT_TCP_MS) ==
		LZ_SUCCESS) {
		if (lzport_socket_receive(0, response, response_size, TIMEOUT_TCP_MS, &received) ==
			LZ_SUCCESS) {
			dbgprint(DBG_NW, "INFO: Successfully received data from networkr\n");
			result = LZ_SUCCESS;
		}
	} else {
		dbgprint(DBG_NW, "WARN: Failed to receive from socket\n");
		result = LZ_ERROR;
	}

	dbgprint(DBG_NW, "INFO: NET - Closing socket\n");

	if (lzport_socket_close(0, TIMEOUT_TCP_MS) != LZ_SUCCESS) {
		dbgprint(DBG_WARN, "WARN: Failed to close socket\n");
	}

exit:
	return result;
}

uint8_t buf[4 * 1460] = { 0 }; // TODO magic number -> maximum of IPD receive

// TODO consider using generic element request function (first adjust it to be capable
// of variable payload lengths)
LZ_RESULT lz_net_update(hdr_type_t update_type, uint8_t *payload, uint32_t payload_size)
{
	lz_auth_hdr_t fw_update_request_hdr = { 0 };
	LZ_RESULT result = LZ_ERROR;

	fw_update_request_hdr.content.magic = LZ_MAGIC;
	memcpy((void *)fw_update_request_hdr.content.nonce, (void *)lz_img_boot_params.info.next_nonce,
		   LEN_NONCE);
	fw_update_request_hdr.content.type = update_type;
	fw_update_request_hdr.content.payload_size = payload_size;
	lz_get_uuid(fw_update_request_hdr.content.uuid);

	// Hash the payload of the ticket (which is only the requested time)
	if (lz_sha256(fw_update_request_hdr.content.digest, payload,
				  fw_update_request_hdr.content.payload_size) != 0) {
		dbgprint(DBG_ERR, "ERROR: Failed to hash payload of ticket\n");
		result = LZ_ERROR;
		return result;
	}

	// Sign the request
	lz_ecc_signature alias_id_sig;
	if (0 != lz_ecdsa_sign_pem(
				 (uint8_t *)&fw_update_request_hdr.content, sizeof(fw_update_request_hdr.content),
				 (lz_ecc_priv_key_pem *)&lz_img_boot_params.info.alias_id_keypair_priv,
				 &alias_id_sig)) {
		dbgprint(DBG_ERR, "ERROR: Failed to sign update request\n");
		result = LZ_ERROR;
		return result;
	}

	memcpy(&fw_update_request_hdr.signature, &alias_id_sig, sizeof(alias_id_sig));

	dbgprint(DBG_INFO, "INFO: Request %s update from server..\n", HDR_TYPE_STRING[update_type]);

	if (lzport_socket_open(0, (char *)lz_data_store.config_data.nw_info.server_ip_addr,
						   lz_data_store.config_data.nw_info.server_port,
						   TIMEOUT_SOCKET_OPEN_MS) != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Failed to open socket\n");
		result = LZ_ERROR;
		goto exit;
	}

	// Copy header and payload into buf
	memcpy((void *)buf, (void *)&fw_update_request_hdr, sizeof(lz_auth_hdr_t));
	memcpy((void *)(buf + sizeof(lz_auth_hdr_t)), (void *)payload, payload_size);

	// Send update request
	if (lzport_socket_send(0, buf, sizeof(lz_auth_hdr_t) + payload_size, TIMEOUT_TCP_MS) !=
		LZ_SUCCESS) {
		dbgprint(DBG_WARN, "WARN: Failed to send data\n");
		result = LZ_ERROR;
		goto exit;
	}

	// Receiving staging header and firmware update
	dbgprint(DBG_INFO, "INFO: Receiving staging header and firmware update..\n");

	uint32_t received_total = 0;
	uint32_t pending = 0;
	uint32_t total_size = 0;
	lz_auth_hdr_t fw_update_response_hdr = { 0 };
	bool header_received = false;
	uint32_t previous_progress = 0;
	do {
		uint32_t received_packet;

		dbgprint(DBG_NW, "INFO: Receiving FW update chunk\n");
		if (lzport_socket_receive(0, buf, sizeof(buf), TIMEOUT_RECEIVE_FW_MS, &received_packet) !=
			LZ_SUCCESS) {
			dbgprint(DBG_ERR, "ERROR: Failed to receive from socket during firmware update\n");
			result = LZ_ERROR;
			goto exit;
		}

		if (!header_received) {
			header_received = true;

			memcpy((void *)&fw_update_response_hdr, (void *)buf, sizeof(lz_auth_hdr_t));

			total_size = fw_update_response_hdr.content.payload_size + sizeof(lz_auth_hdr_t);
			pending = total_size;

			// Print staging header info
			dbgprint(DBG_INFO,
					 "INFO: Received header: %s, total size %d payload size %d, "
					 "magic 0x%x\n",
					 HDR_TYPE_STRING[fw_update_response_hdr.content.type], total_size,
					 fw_update_response_hdr.content.payload_size,
					 fw_update_response_hdr.content.magic);

			dbgprint(DBG_INFO, "INFO: Receiving the update (this may take a while)\n");
		}

		// Set RTS to signal the ESP8266 to pause sending as data cannot be received while writing to flash
		lzport_gpio_set_rts(true);

		// Write data to flash
		if (lz_flash_staging_element(buf, received_packet, total_size, pending) != LZ_SUCCESS) {
			dbgprint(DBG_ERR, "ERROR: Failed to flash staging element\n");
			result = LZ_ERROR;
			goto exit;
		}

		// Reset RTS to signal the ESP8266 to continue sending
		lzport_gpio_set_rts(false);

		received_total += received_packet;
		pending -= received_packet;

		dbgprint(DBG_NW, "INFO: Received FW chunk (received: %d, pending: %d, total size: %d)\n",
				 received_total, pending,
				 fw_update_response_hdr.content.payload_size + sizeof(lz_auth_hdr_t));

		// Indicate progress
		uint32_t progress = (received_total * 100) / fw_update_response_hdr.content.payload_size;
		if (progress >= previous_progress + 10) {
			dbgprint(DBG_INFO, "INFO: %d%%\n", progress);
			previous_progress = progress;
		}

	} while (received_total < total_size);

	dbgprint(DBG_NW, "INFO: Downloading firmware update successful. Closing socket\n");
	result = LZ_SUCCESS;

exit:
	if (lzport_socket_close(0, TIMEOUT_TCP_MS) != LZ_SUCCESS) {
		dbgprint(DBG_WARN, "WARN: Could not close socket\n");
	}

	return result;
}
