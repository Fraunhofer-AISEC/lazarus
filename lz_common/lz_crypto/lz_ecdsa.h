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

#ifndef LZ_CRYPTO_ECDSA_H_
#define LZ_CRYPTO_ECDSA_H_

#ifdef MBEDTLS_CONFIG_FILE

#include "lz_ecc.h"

/**
 * Hashes the data given in data with the length data_length and signs it with the key_pair.
 * Signature will be stored in the sig parameter.
 * Return 0 on success.
 */
int lz_ecdsa_sign(uint8_t *data, size_t data_length, lz_ecc_keypair *key_pair,
				  lz_ecc_signature *sig);

/**
 * Hashes the data given in data with the length data_length and signs it with the given private key.
 * Signature will be stored in the sig parameter.
 * Return 0 on success.
 */
int lz_ecdsa_sign_pem(uint8_t *data, size_t data_length, lz_ecc_priv_key_pem *key,
					  lz_ecc_signature *sig);

/**
 * Verifies the signature sig for data with the length of data_length using key_pair as key.
 * Note: The private part of the key (d) is not used.
 * Return 0 on success.
 */
int lz_ecdsa_verify(uint8_t *data, size_t data_length, lz_ecc_keypair *key_pair,
					lz_ecc_signature *sig);

/**
 * Verifies the signature sig for data with the length of data_length using the key key.
 * Uses only the public part of the ecc_keypair
 * Return 0 on success.
 */
int lz_ecdsa_verify_pub(uint8_t *data, size_t data_length, lz_ecc_keypair *keypair,
						lz_ecc_signature *sig);

/**
 * Verifies the signature sig for data with the length of data_length using the key key.
 * Return 0 on success.
 */
int lz_ecdsa_verify_pub_pem(uint8_t *data, size_t data_length, lz_ecc_pub_key_pem *key,
							const lz_ecc_signature *sig);

#endif /* MBEDTLS_CONFIG_FILE */

#endif
