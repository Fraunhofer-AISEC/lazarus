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

#ifndef LZ_CRYPTO_LZ_ECC_H_
#define LZ_CRYPTO_LZ_ECC_H_

#ifdef MBEDTLS_CONFIG_FILE

#include MBEDTLS_CONFIG_FILE

#if defined(MBEDTLS_PK_WRITE_C)

#include "lz_crypto_common.h"

#include "mbedtls/pk.h"
#include "mbedtls/ecdh.h"

typedef mbedtls_pk_context lz_ecc_keypair;
typedef mbedtls_ecp_point lz_ecc_public_key;
typedef mbedtls_mpi lz_ecc_private_key;

/**
 * Does the same as lz_derive_ecc_keys, but just takes in an uninitialized keypair instead of 2
 * single keys.
 */
int lz_derive_ecc_keypair(lz_ecc_keypair *pub, const void *seed, size_t seed_size);

#if defined(MBEDTLS_PEM_WRITE_C)
/**
 * Exports the public part of the lz_ecc_keypair to a lz_ecc_pub_key_pem. The key in the buffer is in pem format.
 * Returns the length of the key in pem format on success. Otherwise return will be < 0.
 */
int lz_pub_key_to_pem(lz_ecc_keypair *keypair, lz_ecc_pub_key_pem *pem);

/**
 * Exports a lz_ecc_keypair to a lz_ecc_pub_key_pem. The key in the buffer is in pem format.
 * Returns the length of the key in pem format on success. Otherwise return will be < 0.
 */
int lz_priv_key_to_pem(lz_ecc_keypair *keypair, lz_ecc_priv_key_pem *pem);
#endif

#if defined(MBEDTLS_PK_PARSE_C)
/**
 * Imports an lz_ecc_pub_key_pem to the public part of an lz_ecc_keypair. The key in the buffer must be in pem format.
 * Returns 0 on success. If an error occurs, a negative number will be returned.
 *
 * Note: key must be freed after use using `lz_free_keypair`
 */
int lz_pem_to_pub_key(lz_ecc_keypair *keypair, const lz_ecc_pub_key_pem *pem);

/**
 * Imports an ecc_public_key to a lz_ecc_pub_key_pem. The key in the buffer must be in pem format.
 * Returns 0 on success. If an error occurs, a negative number will be returned.
 *
 * Note: key must be freed after use using `lz_free_keypair`
 */
int lz_pem_to_priv_key(lz_ecc_keypair *keypair, const lz_ecc_priv_key_pem *pem);
#endif

/**
 * Access function to the private key of a lz keypar
 */
lz_ecc_private_key *lz_keypair_to_private(lz_ecc_keypair *keypair);

/**
 * Access function to the public key of a lz keypar
 */
lz_ecc_public_key *lz_keypair_to_public(lz_ecc_keypair *keypair);

/**
 * Compares 2 given keys.
 * Returns 0, if the keys are equal.
 */
int lz_compare_public_key(lz_ecc_public_key *k1, lz_ecc_public_key *k2);

/**
 * Cleans up an lz keypair
 */
void lz_free_keypair(lz_ecc_keypair *keypair);

#endif /* MBEDTLS_PK_WRITE_C_ */

#endif /* MBEDTLS_CONFIG_FILE */

#endif /* LZ_CRYPTO_LZ_ECC_H_ */
