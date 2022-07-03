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

#if defined(MBEDTLS_PK_WRITE_C)

#include "crypto_common.h"

#include "mbedtls/pk.h"
#include "mbedtls/ecdh.h"

typedef mbedtls_pk_context ecc_keypair_t;
typedef mbedtls_ecp_point ecc_public_key_t;
typedef mbedtls_mpi ecc_private_key_t;

/**
 * Does the same as lz_derive_ecc_keys, but just takes in an uninitialized keypair instead of 2
 * single keys.
 */
int ecc_derive_keypair(ecc_keypair_t *pub, const void *seed, size_t seed_size);

#if defined(MBEDTLS_PEM_WRITE_C)
/**
 * Exports the public part of the ecc_keypair_t to a ecc_pub_key_pem_t. The key in the buffer is in pem format.
 * Returns the length of the key in pem format on success. Otherwise return will be < 0.
 */
int ecc_pub_key_to_pem(ecc_keypair_t *keypair, ecc_pub_key_pem_t *pem);

/**
 * Exports a ecc_keypair_t to a ecc_pub_key_pem_t. The key in the buffer is in pem format.
 * Returns the length of the key in pem format on success. Otherwise return will be < 0.
 */
int ecc_priv_key_to_pem(ecc_keypair_t *keypair, ecc_priv_key_pem_t *pem);
#endif

#if defined(MBEDTLS_PK_PARSE_C)
/**
 * Imports an ecc_pub_key_pem_t to the public part of an ecc_keypair_t. The key in the buffer must be in pem format.
 * Returns 0 on success. If an error occurs, a negative number will be returned.
 *
 * Note: key must be freed after use using `ecc_free_keypair`
 */
int ecc_pem_to_pub_key(ecc_keypair_t *keypair, const ecc_pub_key_pem_t *pem);

/**
 * Imports an ecc_public_key to a ecc_pub_key_pem_t. The key in the buffer must be in pem format.
 * Returns 0 on success. If an error occurs, a negative number will be returned.
 *
 * Note: key must be freed after use using `ecc_free_keypair`
 */
int ecc_pem_to_priv_key(ecc_keypair_t *keypair, const ecc_priv_key_pem_t *pem);
#endif

/**
 * Access function to the private key of a lz keypar
 */
ecc_private_key_t *ecc_keypair_to_private(ecc_keypair_t *keypair);

/**
 * Access function to the public key of a lz keypar
 */
ecc_public_key_t *ecc_keypair_to_public(ecc_keypair_t *keypair);

/**
 * Compares 2 given keys.
 * Returns 0, if the keys are equal.
 */
int ecc_compare_public_key(ecc_public_key_t *k1, ecc_public_key_t *k2);

/**
 * Cleans up an lz keypair
 */
void ecc_free_keypair(ecc_keypair_t *keypair);

#endif /* MBEDTLS_PK_WRITE_C_ */

#endif /* MBEDTLS_CONFIG_FILE */
