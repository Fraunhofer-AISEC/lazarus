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

#ifdef MBEDTLS_CONFIG_FILE

#include MBEDTLS_CONFIG_FILE

#include "sha256.h"

#ifdef MBEDTLS_SHA256_C

#include "mbedtls/sha256.h"

#include "crypto_common.h"

int sha256(uint8_t *result, const void *data, size_t dataSize)
{
	return mbedtls_sha256_ret(data, dataSize, result, 0);
}

int sha256_two_parts(uint8_t *result, const void *data1, size_t data1Size, const void *data2,
						size_t data2Size)
{
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init(&ctx);
	int re;

	CHECK(mbedtls_sha256_starts_ret(&ctx, 0), "Error creating SHA256 hash (1)");
	CHECK(mbedtls_sha256_update_ret(&ctx, data1, data1Size), "Error creating SHA256 hash (2)");
	CHECK(mbedtls_sha256_update_ret(&ctx, data2, data2Size), "Error creating SHA256 hash (3)");
	CHECK(mbedtls_sha256_finish_ret(&ctx, result), "Error creating SHA256 hash (4)");

clean:
	mbedtls_sha256_free(&ctx);
	return re;
}

#endif

#endif /* MBEDTLS_CONFIG_FILE */
