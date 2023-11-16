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
#include <stdlib.h>
#include "ecdsa.h"
#include "sha256.h"
#include "lz_common.h"
#include "lz_msg_encode.h"
#include "lz_msg_frame.h"
#include "hubrequest.pb-c.h"

// The protobuf protocol supports (theoretically) an infinite number of
// version info structures per "check for update" message. However we restrict
// ourselves to a limited number, because lazarus does not have so many
// components and we want to save stack space while processing.
#define MAX_UPDATE_COMPONENTS 8

static LZ_RESULT calculate_signature(const uint8_t *payload, unsigned payload_len,
									 ecc_signature_t *signature)
{
	int status = ecdsa_sign_pem((uint8_t *)payload, payload_len,
								(ecc_priv_key_pem_t *)lz_alias_id_keypair_priv(), signature);
	if (0 != status) {
		ERROR("ecdsa_sign_pem\n");
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

static LZ_RESULT encode_signed_message(const struct lz_msg_context *context, uint8_t *buffer,
									   const uint8_t *payload, size_t payload_len,
									   size_t *actual_length, bool has_signature)
{
	SignedHubRequestMessage msg;
	ecc_signature_t signature;

	signed_hub_request_message__init(&msg);

	if (has_signature) {
		if (calculate_signature(payload, payload_len, &signature) != LZ_SUCCESS)
			return LZ_ERROR;

		msg.signature.data = signature.sig;
		msg.signature.len = signature.length;
	}

	msg.payload.data = (uint8_t *)payload;
	msg.payload.len = payload_len;
	msg.uuid.data = context->uuid;
	msg.uuid.len = LEN_UUID_V4_BIN;

	size_t msg_len = signed_hub_request_message__get_packed_size(&msg);

	if (lz_msg_frame_write_header(buffer, msg_len) != LZ_SUCCESS) {
		ERROR("Failed to write frame header\n");
		return LZ_ERROR;
	}

	size_t header_size = lz_msg_frame_header_size();
	*actual_length = signed_hub_request_message__pack(&msg, buffer + header_size);
	*actual_length += header_size;
	return LZ_SUCCESS;
}

static LZ_RESULT get_length_signed_message(const struct lz_msg_context *context, size_t payload_len,
										   unsigned *msg_len_out)
{
	SignedHubRequestMessage msg;

	signed_hub_request_message__init(&msg);
	msg.payload.data = NULL;
	msg.payload.len = payload_len;
	msg.uuid.data = NULL;
	msg.uuid.len = LEN_UUID_V4_BIN;
	msg.signature.data = NULL;
	msg.signature.len = MAX_SIG_ECP_DER_BYTES;

	size_t msg_len = signed_hub_request_message__get_packed_size(&msg);
	size_t frame_len = msg_len + lz_msg_frame_header_size();
	*msg_len_out = frame_len;
	return LZ_SUCCESS;
}

LZ_RESULT lz_msg_encode_alias_id(const struct lz_msg_context *context, uint8_t *buffer,
								 size_t *actual_length, const uint8_t *cert, unsigned cert_len)
{
	HubRequestMessage msg;
	AliasIdCert submsg;
	hub_request_message__init(&msg);
	alias_id_cert__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_ALIASID;
	msg.aliasid = &submsg;
	submsg.certificate.data = (uint8_t *)cert;
	submsg.certificate.len = cert_len;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	uint8_t hub_request_buffer[msg_len];
	hub_request_message__pack(&msg, hub_request_buffer);

	return encode_signed_message(context, buffer, hub_request_buffer, msg_len, actual_length,
								 false);
}

LZ_RESULT lz_msg_get_length_alias_id(const struct lz_msg_context *context, unsigned *msg_len_out,
									 const uint8_t *cert, unsigned cert_len)
{
	HubRequestMessage msg;
	AliasIdCert submsg;
	hub_request_message__init(&msg);
	alias_id_cert__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_ALIASID;
	msg.aliasid = &submsg;
	submsg.certificate.data = (uint8_t *)cert;
	submsg.certificate.len = cert_len;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	return get_length_signed_message(context, msg_len, msg_len_out);
}

LZ_RESULT lz_msg_encode_refresh_boot_ticket(const struct lz_msg_context *context, uint8_t *buffer,
											size_t *actual_length)
{
	HubRequestMessage msg;
	RefreshBootTicket submsg;
	hub_request_message__init(&msg);
	refresh_boot_ticket__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_BOOT_TICKET;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.bootticket = &submsg;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	uint8_t hub_request_buffer[msg_len];
	hub_request_message__pack(&msg, hub_request_buffer);

	return encode_signed_message(context, buffer, hub_request_buffer, msg_len, actual_length, true);
}

LZ_RESULT lz_msg_get_length_refresh_boot_ticket(const struct lz_msg_context *context,
												unsigned *msg_len_out)
{
	HubRequestMessage msg;
	RefreshBootTicket submsg;
	hub_request_message__init(&msg);
	refresh_boot_ticket__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_BOOT_TICKET;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.bootticket = &submsg;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	return get_length_signed_message(context, msg_len, msg_len_out);
}

LZ_RESULT lz_msg_encode_refresh_awdt(const struct lz_msg_context *context, uint8_t *buffer,
									 size_t *actual_length, uint32_t requested_time_ms)
{
	HubRequestMessage msg;
	AwdtRefresh submsg;
	hub_request_message__init(&msg);
	awdt_refresh__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_AWDT;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.awdt = &submsg;
	submsg.timems = requested_time_ms;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	uint8_t hub_request_buffer[msg_len];
	hub_request_message__pack(&msg, hub_request_buffer);

	return encode_signed_message(context, buffer, hub_request_buffer, msg_len, actual_length, true);
}

LZ_RESULT lz_msg_get_length_refresh_awdt(const struct lz_msg_context *context,
										 unsigned *msg_len_out)
{
	HubRequestMessage msg;
	AwdtRefresh submsg;
	hub_request_message__init(&msg);
	awdt_refresh__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_AWDT;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.awdt = &submsg;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	return get_length_signed_message(context, msg_len, msg_len_out);
}

LZ_RESULT lz_msg_get_length_sensor_data(const struct lz_msg_context *context, unsigned *msg_len_out)
{
	HubRequestMessage msg;
	SensorData submsg;
	hub_request_message__init(&msg);
	sensor_data__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_SENSOR_DATA;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.sensordata = &submsg;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	return get_length_signed_message(context, msg_len, msg_len_out);
}

LZ_RESULT lz_msg_encode_sensor_data(const struct lz_msg_context *context, uint8_t *buffer,
									size_t *actual_length, uint32_t index, float temperature,
									float humidity)
{
	HubRequestMessage msg;
	SensorData submsg;
	hub_request_message__init(&msg);
	sensor_data__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_SENSOR_DATA;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.sensordata = &submsg;
	submsg.index = index;
	submsg.temperature = temperature;
	submsg.humidity = humidity;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	uint8_t hub_request_buffer[msg_len];
	hub_request_message__pack(&msg, hub_request_buffer);

	return encode_signed_message(context, buffer, hub_request_buffer, msg_len, actual_length, true);
}

static const char *update_type_as_string(enum lz_msg_update_type type)
{
	switch (type) {
	case LZ_MSG_UPDATE_TYPE_APP:
		return "app";
	case LZ_MSG_UPDATE_TYPE_UDOWNLOADER:
		return "udownloader";
	case LZ_MSG_UPDATE_TYPE_CPATCHER:
		return "cpatcher";
	case LZ_MSG_UPDATE_TYPE_CORE:
		return "core";
	case LZ_MSG_UPDATE_TYPE_CONFIG:
		return "config";
	default:
		return "unknown";
	}
}

LZ_RESULT lz_msg_get_length_update(const struct lz_msg_context *context, unsigned *msg_len_out,
								   enum lz_msg_update_type type)
{
	HubRequestMessage msg;
	FirmwareUpdate submsg;
	hub_request_message__init(&msg);
	firmware_update__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_FW_UPDATE;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.fwupdate = &submsg;
	submsg.type = (char *)update_type_as_string(type);

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	return get_length_signed_message(context, msg_len, msg_len_out);
}

LZ_RESULT lz_msg_encode_update(const struct lz_msg_context *context, uint8_t *buffer,
							   size_t *actual_length, enum lz_msg_update_type type)
{
	HubRequestMessage msg;
	FirmwareUpdate submsg;
	hub_request_message__init(&msg);
	firmware_update__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_FW_UPDATE;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.fwupdate = &submsg;
	submsg.type = (char *)update_type_as_string(type);

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	uint8_t hub_request_buffer[msg_len];
	hub_request_message__pack(&msg, hub_request_buffer);

	return encode_signed_message(context, buffer, hub_request_buffer, msg_len, actual_length, true);
}

LZ_RESULT lz_msg_get_length_reassoc(const struct lz_msg_context *context, unsigned *msg_len_out,
									struct lz_msg_reassoc_info info)
{
	HubRequestMessage msg;
	ReassociateDevice submsg;
	hub_request_message__init(&msg);
	reassociate_device__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_REASSOC_DEVICE;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.reassocdevice = &submsg;
	submsg.uuid.data = info.uuid;
	submsg.uuid.len = info.uuid_len;
	submsg.auth.data = info.auth;
	submsg.auth.len = info.auth_len;
	submsg.deviceidcert.data = info.dev_id_csr;
	submsg.deviceidcert.len = info.dev_id_csr_len;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	return get_length_signed_message(context, msg_len, msg_len_out);
}

LZ_RESULT lz_msg_encode_reassoc(const struct lz_msg_context *context, uint8_t *buffer,
								size_t *actual_length, struct lz_msg_reassoc_info info)
{
	HubRequestMessage msg;
	ReassociateDevice submsg;
	hub_request_message__init(&msg);
	reassociate_device__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_REASSOC_DEVICE;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.reassocdevice = &submsg;
	submsg.uuid.data = info.uuid;
	submsg.uuid.len = info.uuid_len;
	submsg.auth.data = info.auth;
	submsg.auth.len = info.auth_len;
	submsg.deviceidcert.data = info.dev_id_csr;
	submsg.deviceidcert.len = info.dev_id_csr_len;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	uint8_t hub_request_buffer[msg_len];
	hub_request_message__pack(&msg, hub_request_buffer);

	return encode_signed_message(context, buffer, hub_request_buffer, msg_len, actual_length, true);
}

LZ_RESULT lz_msg_get_length_check_for_update(const struct lz_msg_context *context,
											 unsigned *msg_len_out, enum lz_msg_update_type types[],
											 unsigned num_types)
{
	const char *types_str[MAX_UPDATE_COMPONENTS];
	if (num_types > MAX_UPDATE_COMPONENTS)
		return LZ_ERROR;

	for (int i = 0; i < num_types; i++)
		types_str[i] = update_type_as_string(types[i]);

	HubRequestMessage msg;
	CheckForUpdate submsg;
	hub_request_message__init(&msg);
	check_for_update__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_CHECK_FOR_UPDATE;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.checkforupdate = &submsg;
	submsg.components = (char **)types_str;
	submsg.n_components = num_types;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	return get_length_signed_message(context, msg_len, msg_len_out);
}

LZ_RESULT lz_msg_encode_check_for_update(const struct lz_msg_context *context, uint8_t *buffer,
										 size_t *actual_length, enum lz_msg_update_type types[],
										 unsigned num_types)
{
	const char *types_str[MAX_UPDATE_COMPONENTS];
	if (num_types > MAX_UPDATE_COMPONENTS)
		return LZ_ERROR;

	for (int i = 0; i < num_types; i++)
		types_str[i] = update_type_as_string(types[i]);

	HubRequestMessage msg;
	CheckForUpdate submsg;
	hub_request_message__init(&msg);
	check_for_update__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_CHECK_FOR_UPDATE;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.checkforupdate = &submsg;
	submsg.components = (char **)types_str;
	submsg.n_components = num_types;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	uint8_t hub_request_buffer[msg_len];
	hub_request_message__pack(&msg, hub_request_buffer);

	return encode_signed_message(context, buffer, hub_request_buffer, msg_len, actual_length, true);
}

LZ_RESULT lz_msg_encode_request_user_input(const struct lz_msg_context *context, uint8_t *buffer,
										   size_t *actual_length)
{
	HubRequestMessage msg;
	UserInput submsg;
	hub_request_message__init(&msg);
	user_input__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_USER_INPUT;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.userinput = &submsg;
	submsg.type = 0x0;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	uint8_t hub_request_buffer[msg_len];
	hub_request_message__pack(&msg, hub_request_buffer);

	return encode_signed_message(context, buffer, hub_request_buffer, msg_len, actual_length, true);
}

LZ_RESULT lz_msg_get_length_request_user_input(const struct lz_msg_context *context,
											   unsigned *msg_len_out)
{
	HubRequestMessage msg;
	UserInput submsg;
	hub_request_message__init(&msg);
	user_input__init(&submsg);
	msg.magic = LZ_MAGIC;
	msg.has_nonce = true;
	msg.nonce.data = context->nonce;
	msg.nonce.len = LEN_NONCE;
	msg.payload_case = HUB_REQUEST_MESSAGE__PAYLOAD_USER_INPUT;
	msg.userinput = &submsg;

	size_t msg_len = hub_request_message__get_packed_size(&msg);
	return get_length_signed_message(context, msg_len, msg_len_out);
}