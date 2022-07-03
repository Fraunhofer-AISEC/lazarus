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

#if defined(MBEDTLS_CHACHAPOLY_C)

int chacha20_poly1305_encrypt(const unsigned char *input, uint32_t input_len,
								 unsigned char *output, uint32_t output_len, uint8_t *nonce,
								 size_t nonce_len, const uint8_t *aad, size_t aad_len,
								 uint8_t *key);

int chacha20_poly1305_decrypt(const uint8_t *input, const uint32_t input_len, uint8_t *output,
								 const uint32_t output_len, uint8_t *nonce, size_t nonce_len,
								 const uint8_t *aad, size_t aad_len, uint8_t *key);

#endif

#endif /* MBEDTLS_CONFIG_FILE */