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

#ifndef LZ_NET_LZ_MSG_DECODE_H_
#define LZ_NET_LZ_MSG_DECODE_H_

#include <stdint.h>
#include <time.h>
#include "lz_error.h"

#define LZ_MSG_MAX_COMPONENTS 8

LZ_RESULT lz_msg_decode_alias_id(
		const uint8_t *buffer,
		unsigned msg_len);

LZ_RESULT lz_msg_decode_awdt_refresh(
		const uint8_t *buffer,
		unsigned msg_len,
		uint32_t *time_ms,
		uint8_t nonce[LEN_NONCE]);

LZ_RESULT lz_msg_decode_refresh_boot_ticket(
		const uint8_t *buffer,
		unsigned msg_len,
		uint8_t nonce_out[LEN_NONCE]);

LZ_RESULT lz_msg_decode_sensor_data(
		const uint8_t *buffer,
		unsigned msg_len);

LZ_RESULT lz_msg_decode_reassoc(
		const uint8_t *buffer,
		unsigned msg_len,
		unsigned *payload_bytes,
		uint8_t nonce_out[LEN_NONCE]);

LZ_RESULT lz_msg_decode_update(
		const uint8_t *buffer,
		unsigned msg_len,
		unsigned *payload_bytes,
		uint8_t nonce_out[LEN_NONCE]);

struct lz_msg_version_info {
	char name[20];
	char newest_version[10];
	time_t issue_time;
};

struct lz_msg_check_for_update_response {
	uint8_t nonce[LEN_NONCE];
	unsigned num_components;
	struct lz_msg_version_info components[LZ_MSG_MAX_COMPONENTS];
};

LZ_RESULT lz_msg_decode_check_for_update(
		const uint8_t *buffer,
		unsigned msg_len,
		struct lz_msg_check_for_update_response *response);

LZ_RESULT lz_msg_decode_user_input(
		const uint8_t *buffer,
		unsigned msg_len,
		uint8_t *user_input,
		uint32_t *user_input_len,
		bool *user_input_available);

#endif /* LZ_NET_LZ_MSG_DECODE_H_ */
