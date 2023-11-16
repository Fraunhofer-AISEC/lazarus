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

#ifndef LZ_NET_LZ_MSG_ENCODE_H_
#define LZ_NET_LZ_MSG_ENCODE_H_

#include <stdint.h>
#include <stddef.h>
#include "lz_error.h"

struct lz_msg_context
{
	uint8_t *uuid;
	uint8_t *nonce;
};

enum lz_msg_update_type
{
	LZ_MSG_UPDATE_TYPE_APP,
	LZ_MSG_UPDATE_TYPE_UDOWNLOADER,
	LZ_MSG_UPDATE_TYPE_CPATCHER,
	LZ_MSG_UPDATE_TYPE_CORE,
	LZ_MSG_UPDATE_TYPE_CONFIG,
};

LZ_RESULT lz_msg_get_length_alias_id(
		const struct lz_msg_context *context,
		unsigned *msg_len_out,
		const uint8_t *cert,
		unsigned cert_len);

LZ_RESULT lz_msg_encode_alias_id(
		const struct lz_msg_context *context,
		uint8_t *buffer,
		size_t *actual_length,
		const uint8_t *cert,
		unsigned cert_len);

LZ_RESULT lz_msg_get_length_refresh_boot_ticket(
		const struct lz_msg_context *context,
		unsigned *msg_len_out);

LZ_RESULT lz_msg_encode_refresh_boot_ticket(
		const struct lz_msg_context *context,
		uint8_t *buffer,
		size_t *actual_length);

LZ_RESULT lz_msg_get_length_refresh_awdt(
		const struct lz_msg_context *context,
		unsigned *msg_len_out);

LZ_RESULT lz_msg_encode_refresh_awdt(
		const struct lz_msg_context *context,
		uint8_t *buffer,
		size_t *actual_length,
		uint32_t requested_time_ms);

LZ_RESULT lz_msg_get_length_sensor_data(
		const struct lz_msg_context *context,
		unsigned *msg_len_out);

LZ_RESULT lz_msg_encode_sensor_data(
		const struct lz_msg_context *context,
		uint8_t *buffer,
		size_t *actual_length,
		uint32_t index,
		float temperature,
		float humidity);

LZ_RESULT lz_msg_get_length_update(
		const struct lz_msg_context *context,
		unsigned *msg_len_out,
		enum lz_msg_update_type type);

LZ_RESULT lz_msg_encode_update(
		const struct lz_msg_context *context,
		uint8_t *buffer,
		size_t *actual_length,
		enum lz_msg_update_type type);

struct lz_msg_reassoc_info {
	uint8_t *uuid;
	unsigned uuid_len;
	uint8_t *auth;
	unsigned auth_len;
	uint8_t *dev_id_csr;
	unsigned dev_id_csr_len;
};

LZ_RESULT lz_msg_get_length_reassoc(
		const struct lz_msg_context *context,
		unsigned *msg_len_out,
		struct lz_msg_reassoc_info info);

LZ_RESULT lz_msg_encode_reassoc(
		const struct lz_msg_context *context,
		uint8_t *buffer,
		size_t *actual_length,
		struct lz_msg_reassoc_info info);

LZ_RESULT lz_msg_get_length_check_for_update(
		const struct lz_msg_context *context,
		unsigned *msg_len_out,
		enum lz_msg_update_type types[],
		unsigned num_types);

LZ_RESULT lz_msg_encode_check_for_update(
		const struct lz_msg_context *context,
		uint8_t *buffer,
		size_t *actual_length,
		enum lz_msg_update_type types[],
		unsigned num_types);

LZ_RESULT lz_msg_get_length_request_user_input(
		const struct lz_msg_context *context,
		unsigned *msg_len_out);

LZ_RESULT lz_msg_encode_request_user_input(
		const struct lz_msg_context *context,
		uint8_t *buffer,
		size_t *actual_length);

#endif /* LZ_NET_LZ_MSG_ENCODE_H_ */
