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

#include "lzport_debug_output.h"
#include "lzport_rng.h"

#ifdef MBEDTLS_CONFIG_FILE
#include "mbedtls/memory_buffer_alloc.h"
#endif

/** Crypto definition */
#define SHA256_DIGEST_LENGTH 32
#define SYM_KEY_LENGTH (16 + 16)

// Check lz_common/mbedtls/library/pkwrite.c:463 for calculation
#define MAX_PUB_ECP_DER_BYTES 162
#define MAX_PUB_ECP_PEM_BYTES (4 * MAX_PUB_ECP_DER_BYTES / 3) + 3 + 26 + 24 + 10
// Check lz_common/mbedtls/library/pkwrite.c:476 for calculation
#define MAX_PRIV_ECP_DER_BYTES 173
#define MAX_PRIV_ECP_PEM_BYTES (4 * MAX_PRIV_ECP_DER_BYTES / 3) + 3 + 26 + 24 + 10

#define MAX_SIG_ECP_DER_BYTES 80

typedef struct {
	char key[MAX_PUB_ECP_PEM_BYTES];
	// Length is not needed, since it can be figured out with strnlen(key, MAX_PUB_ECP_PEM_BYTES)-
} ecc_pub_key_pem_t;

typedef struct {
	char key[MAX_PRIV_ECP_PEM_BYTES];
	// Length is not needed, since it can be figured out with strnlen(key, MAX_PUB_ECP_PEM_BYTES)-
} ecc_priv_key_pem_t;

typedef struct {
	uint8_t sig[MAX_SIG_ECP_DER_BYTES];
	uint32_t length;
} ecc_signature_t;

#define CHECK(func, err)                                                                           \
	do {                                                                                           \
		if ((re = func) < 0) {                                                                     \
			INFO("ERROR: %s (code: -0x%04x)\n", err, (unsigned int)-re);                           \
			goto clean;                                                                            \
		}                                                                                          \
	} while (0);

int crypto_rand(void *rng_state, unsigned char *output, size_t len);
