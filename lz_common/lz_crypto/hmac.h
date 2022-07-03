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

#pragma once

#ifdef MBEDTLS_CONFIG_FILE

#include MBEDTLS_CONFIG_FILE

#ifdef MBEDTLS_MD_C

#include <stdint.h>

/**
 * Calculates the SHA256 hmac of the data buffer and stores it into the result
 * buffer
 * @param[out] result   The buffer in which the result will be stored (must be
 *                      at least SHA256_DIGEST_SIZE (32) bytes large)
 * @param[in]  data     The data over which the hmac should be computed
 * @param[in]  dataSize The size of the data buffer
 * @param[in]  key      The key to be used for the hmac computation
 * @param[in]  keySize  The size of the key
 *
 * @return 0 on success. If an error occured, returns a non-0 int
 */

int hmac_sha256(uint8_t *result, const void *data, size_t dataSize, const uint8_t *key,
				   size_t keySize);

#endif

#endif /* MBEDTLS_CONFIG_FILE */
