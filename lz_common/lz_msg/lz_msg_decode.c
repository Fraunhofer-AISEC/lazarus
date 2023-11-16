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
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lz_common.h"
#include "lz_msg_decode.h"
#include "ecdsa.h"
#include "lzport_debug_output.h"
#include "hubresponse.pb-c.h"
#include "bootticket_response.pb-c.h"

static LZ_RESULT check_signature(SignedHubResponse *msg)
{
	if (msg->signature.len > MAX_SIG_ECP_DER_BYTES) {
		ERROR("Signature is too long (%d bytes)\n", (int)msg->signature.len);
		return LZ_ERROR;
	}

	ecc_signature_t signature;
	memcpy(signature.sig, msg->signature.data, msg->signature.len);
	signature.length = msg->signature.len;

	if (ecdsa_verify_pub_pem(
			msg->payload.data, msg->payload.len,
			(ecc_pub_key_pem_t *)&lz_data_store.trust_anchors.info.management_pub_key,
			&signature) != 0) {
		ERROR("Could not verify signature of message\n");
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

static LZ_RESULT decode_signed_message(SignedHubResponse__Type expected_type, const uint8_t *buf,
									   size_t buf_len, SignedHubResponse **msg_out)
{
	SignedHubResponse *msg = signed_hub_response__unpack(NULL, buf_len, buf);
	if (!msg) {
		ERROR("Failed to decode signed hub response\n");
		return LZ_ERROR;
	}

	if (msg->status == SIGNED_HUB_RESPONSE__STATUS__NAK) {
		INFO("Received response NAK. Server refused request.\n");
		goto _free_msg;
	} else if (msg->status != SIGNED_HUB_RESPONSE__STATUS__ACK) {
		ERROR("Invalid value in status field.\n");
		goto _free_msg;
	}

	if (!msg->has_payload) {
		ERROR("Hub response has been ACK'ed, but has no payload.\n");
		goto _free_msg;
	}

	if (!msg->has_signature) {
		ERROR("Hub response has been ACK'ed, but has no signature.\n");
		goto _free_msg;
	}

	if (check_signature(msg) != LZ_SUCCESS) {
		ERROR("Signature of message is invalid\n");
		goto _free_msg;
	}

	if (!msg->has_type) {
		ERROR("Type field in protobuf response is not set\n");
		goto _free_msg;
	}
	if (msg->type != expected_type) {
		ERROR("Unexpected response message type\n");
		goto _free_msg;
	}

	VERB("Signature of message is valid\n");

	*msg_out = msg;
	return LZ_SUCCESS;

_free_msg:
	signed_hub_response__free_unpacked(msg, NULL);
	return LZ_ERROR;
}

LZ_RESULT lz_msg_decode_alias_id(const uint8_t *buffer, unsigned msg_len)
{
	LZ_RESULT ret = LZ_SUCCESS;

	SignedHubResponse *signed_msg;
	if (decode_signed_message(SIGNED_HUB_RESPONSE__TYPE__ALIASID, buffer, msg_len, &signed_msg) !=
		LZ_SUCCESS)
		return LZ_ERROR;

	HubResponseAliasId *msg =
		hub_response_alias_id__unpack(NULL, signed_msg->payload.len, signed_msg->payload.data);

	signed_hub_response__free_unpacked(signed_msg, NULL);
	if (!msg) {
		ERROR("Failed to parse protobuf message\n");
		return LZ_ERROR;
	}

	hub_response_alias_id__free_unpacked(msg, NULL);
	return ret;
}

LZ_RESULT lz_msg_decode_awdt_refresh(const uint8_t *buffer, unsigned msg_len, uint32_t *time_ms,
									 uint8_t nonce[LEN_NONCE])
{
	LZ_RESULT ret = LZ_SUCCESS;

	SignedHubResponse *signed_msg;
	if (decode_signed_message(SIGNED_HUB_RESPONSE__TYPE__AWDT, buffer, msg_len, &signed_msg) !=
		LZ_SUCCESS)
		return LZ_ERROR;

	HubResponseAwdtRefresh *msg =
		hub_response_awdt_refresh__unpack(NULL, signed_msg->payload.len, signed_msg->payload.data);

	signed_hub_response__free_unpacked(signed_msg, NULL);
	if (!msg) {
		ERROR("Failed to parse protobuf message\n");
		return LZ_ERROR;
	}

	if (msg->nonce.len == LEN_NONCE) {
		memcpy(nonce, msg->nonce.data, LEN_NONCE);
		*time_ms = msg->timems;
	} else {
		ERROR("Invalid length for nonce in protobuf message\n");
		ret = LZ_ERROR;
	}

	hub_response_awdt_refresh__free_unpacked(msg, NULL);
	return ret;
}

LZ_RESULT lz_msg_decode_refresh_boot_ticket(const uint8_t *buffer, unsigned msg_len,
											uint8_t nonce_out[LEN_NONCE])
{
	LZ_RESULT ret = LZ_SUCCESS;

	SignedHubResponse *signed_msg;
	if (decode_signed_message(SIGNED_HUB_RESPONSE__TYPE__BOOTTICKET, buffer, msg_len,
							  &signed_msg) != LZ_SUCCESS)
		return LZ_ERROR;

	HubResponseRefreshBootTicket *msg = hub_response_refresh_boot_ticket__unpack(
		NULL, signed_msg->payload.len, signed_msg->payload.data);

	signed_hub_response__free_unpacked(signed_msg, NULL);
	if (!msg) {
		ERROR("Failed to parse protobuf message\n");
		return LZ_ERROR;
	}

	if (msg->firmware_info_case != HUB_RESPONSE_REFRESH_BOOT_TICKET__FIRMWARE_INFO_DICEPP) {
		ERROR("Boot ticket response is not for Dice++\n");
		ret = LZ_ERROR;
		goto _free_msg;
	}

	if (msg->nonce.len == LEN_NONCE) {
		memcpy(nonce_out, msg->nonce.data, LEN_NONCE);
	} else {
		ERROR("Length of nonce does not match (expected=%d, got=%d)\n", LEN_NONCE, msg->nonce.len);
		ret = LZ_ERROR;
	}

_free_msg:
	hub_response_refresh_boot_ticket__free_unpacked(msg, NULL);
	return ret;
}

LZ_RESULT lz_msg_decode_sensor_data(const uint8_t *buffer, unsigned msg_len)
{
	SignedHubResponse *signed_msg;
	if (decode_signed_message(SIGNED_HUB_RESPONSE__TYPE__SENSORDATA, buffer, msg_len,
							  &signed_msg) != LZ_SUCCESS)
		return LZ_ERROR;

	HubResponseSensorData *msg =
		hub_response_sensor_data__unpack(NULL, signed_msg->payload.len, signed_msg->payload.data);

	signed_hub_response__free_unpacked(signed_msg, NULL);
	if (!msg) {
		ERROR("Failed to parse protobuf message\n");
		return LZ_ERROR;
	}

	hub_response_sensor_data__free_unpacked(msg, NULL);
	return LZ_SUCCESS;
}

static LZ_RESULT decode_update_generic(SignedHubResponse__Type expected_type, const uint8_t *buffer,
									   unsigned msg_len, unsigned *payload_bytes,
									   uint8_t nonce_out[LEN_NONCE])
{
	int ret = LZ_SUCCESS;
	SignedHubResponse *signed_msg;
	if (decode_signed_message(expected_type, buffer, msg_len, &signed_msg) != LZ_SUCCESS)
		return LZ_ERROR;

	HubResponseUpdate *msg =
		hub_response_update__unpack(NULL, signed_msg->payload.len, signed_msg->payload.data);

	signed_hub_response__free_unpacked(signed_msg, NULL);
	if (!msg) {
		ERROR("Failed to parse protobuf message\n");
		return LZ_ERROR;
	}

	if (msg->nonce.len == LEN_NONCE) {
		memcpy(nonce_out, msg->nonce.data, LEN_NONCE);
	} else {
		ERROR("Length of nonce does not match (expected=%d, got=%d)\n", LEN_NONCE, msg->nonce.len);
		ret = LZ_ERROR;
	}

	*payload_bytes = msg->payloadnumbytes;
	hub_response_update__free_unpacked(msg, NULL);
	return ret;
}

LZ_RESULT lz_msg_decode_update(const uint8_t *buffer, unsigned msg_len, unsigned *payload_bytes,
							   uint8_t nonce_out[LEN_NONCE])
{
	return decode_update_generic(SIGNED_HUB_RESPONSE__TYPE__FWUPDATE, buffer, msg_len,
								 payload_bytes, nonce_out);
}

LZ_RESULT lz_msg_decode_reassoc(const uint8_t *buffer, unsigned msg_len, unsigned *payload_bytes,
								uint8_t nonce_out[LEN_NONCE])
{
	return decode_update_generic(SIGNED_HUB_RESPONSE__TYPE__REASSOC, buffer, msg_len, payload_bytes,
								 nonce_out);
}

static LZ_RESULT copy_string_safe(char *target, size_t target_size, const char *source)
{
	size_t len = strlen(source);
	if (len >= target_size) {
		ERROR("String inside protobuf message is bigger than buffer\n");
		return LZ_ERROR;
	}

	memcpy(target, source, len);
	target[len] = '\0';
	return LZ_SUCCESS;
}

static LZ_RESULT copy_version_info(struct lz_msg_version_info *dest,
								   HubResponseCheckForUpdate__VersionInfo *src)
{
	if (copy_string_safe(dest->name, sizeof(dest->name), src->name) != LZ_SUCCESS) {
		return LZ_ERROR;
	}

	if (copy_string_safe(dest->newest_version, sizeof(dest->newest_version), src->newestversion) !=
		LZ_SUCCESS) {
		return LZ_ERROR;
	}

	dest->issue_time = src->issuetime;
	return LZ_SUCCESS;
}

LZ_RESULT lz_msg_decode_check_for_update(const uint8_t *buffer, unsigned msg_len,
										 struct lz_msg_check_for_update_response *response)
{
	int ret = LZ_SUCCESS;
	SignedHubResponse *signed_msg;
	if (decode_signed_message(SIGNED_HUB_RESPONSE__TYPE__CHECKFORUPDATE, buffer, msg_len,
							  &signed_msg) != LZ_SUCCESS)
		return LZ_ERROR;

	HubResponseCheckForUpdate *msg = hub_response_check_for_update__unpack(
		NULL, signed_msg->payload.len, signed_msg->payload.data);

	signed_hub_response__free_unpacked(signed_msg, NULL);
	if (!msg) {
		ERROR("Failed to parse protobuf message\n");
		return LZ_ERROR;
	}

	if (msg->nonce.len == LEN_NONCE) {
		memcpy(response->nonce, msg->nonce.data, LEN_NONCE);
	} else {
		ERROR("Length of nonce does not match (expected=%d, got=%d)\n", LEN_NONCE, msg->nonce.len);
		ret = LZ_ERROR;
		goto _free_msg;
	}

	if (msg->n_components > LZ_MSG_MAX_COMPONENTS) {
		ERROR("Too many versions per \"check for update\" message\n");
		ret = LZ_ERROR;
		goto _free_msg;
	}

	response->num_components = msg->n_components;
	for (int i = 0; i < msg->n_components; i++) {
		if (copy_version_info(&response->components[i], msg->components[i]) != LZ_SUCCESS) {
			ret = LZ_ERROR;
			goto _free_msg;
		}
	}

_free_msg:
	hub_response_check_for_update__free_unpacked(msg, NULL);
	return ret;
}

LZ_RESULT lz_msg_decode_user_input(const uint8_t *buffer, unsigned msg_len, uint8_t *user_input,
								   uint32_t *user_input_len, bool *user_input_available)
{
	LZ_RESULT ret = LZ_SUCCESS;

	SignedHubResponse *signed_msg;
	if (decode_signed_message(SIGNED_HUB_RESPONSE__TYPE__USERINPUT, buffer, msg_len, &signed_msg) !=
		LZ_SUCCESS)
		return LZ_ERROR;

	HubResponseUserInput *msg =
		hub_response_user_input__unpack(NULL, signed_msg->payload.len, signed_msg->payload.data);

	signed_hub_response__free_unpacked(signed_msg, NULL);
	if (!msg) {
		ERROR("Failed to parse protobuf message\n");
		return LZ_ERROR;
	}

	if (msg->userinput.len > *user_input_len) {
		ERROR("Invalid length for user input in protobuf message\n");
		ret = LZ_ERROR;
	} else {
		memcpy(user_input, msg->userinput.data, msg->userinput.len);
		*user_input_len = msg->userinput.len;
		*user_input_available = msg->available;
	}

	hub_response_user_input__free_unpacked(msg, NULL);
	return ret;
}