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

#ifndef LZ_NET_LZ_MSG_FRAME_H_
#define LZ_NET_LZ_MSG_FRAME_H_

#include <stddef.h>
#include "lz_error.h"

struct lz_msg_istream {
	LZ_RESULT (*callback)(struct lz_msg_istream *stream, uint8_t *buffer, size_t length);
	void *arg;
};

LZ_RESULT lz_msg_frame_read_size(
		struct lz_msg_istream *stream,
		unsigned *frame_size);

LZ_RESULT lz_msg_frame_read_to_buffer(
		struct lz_msg_istream *stream,
		uint8_t *buffer,
		unsigned frame_length);

LZ_RESULT lz_msg_frame_write_header(
		uint8_t *buffer,
		size_t payload_size);

size_t lz_msg_frame_header_size(void);

#endif /* LZ_NET_LZ_MSG_FRAME_H_ */
