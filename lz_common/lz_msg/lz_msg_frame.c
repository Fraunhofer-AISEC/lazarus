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
#include "lzport_debug_output.h"
#include "lz_msg_frame.h"

#define FRAME_HEADER_SIZE 2
#define MAX_FRAME_LENGTH 1000

LZ_RESULT lz_msg_frame_read_size(struct lz_msg_istream *stream, unsigned *frame_length)
{
	uint8_t buffer[FRAME_HEADER_SIZE];
	LZ_RESULT result = LZ_ERROR;

	if ((result = stream->callback(stream, buffer, sizeof(buffer))) != LZ_SUCCESS) {
		ERROR("Failed to read header for protobuf message\n");
		return result;
	}

	uint16_t len = buffer[0] << 8 | buffer[1];
	*frame_length = (unsigned)len;

	if (*frame_length > MAX_FRAME_LENGTH) {
		ERROR("Received message is too big (%d bytes)\n", *frame_length);
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

LZ_RESULT lz_msg_frame_read_to_buffer(struct lz_msg_istream *stream, uint8_t *buffer,
									  unsigned frame_length)
{
	LZ_RESULT result = LZ_ERROR;
	if ((result = stream->callback(stream, buffer, frame_length)) != LZ_SUCCESS) {
		ERROR("Failed to read protobuf message\n");
		return result;
	}

	return LZ_SUCCESS;
}

LZ_RESULT lz_msg_frame_write_header(uint8_t *buffer, size_t payload_size)
{
	if (payload_size > MAX_FRAME_LENGTH) {
		ERROR("Message to be sent is too big (%d bytes)\n", payload_size);
		return LZ_ERROR;
	}

	// The frame size is a two byte encoded number in network byte order.
	buffer[0] = (payload_size >> 8) & 0xff;
	buffer[1] = payload_size & 0xff;
	return LZ_SUCCESS;
}

size_t lz_msg_frame_header_size(void)
{
	return FRAME_HEADER_SIZE;
}
