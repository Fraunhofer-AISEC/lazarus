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

#include "mbedtls/pk.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/hkdf.h"
#include "ecc.h"
#include "chacha20_poly1305.h"
#include "ecdh.h"

#if defined(MBEDTLS_HKDF_C) && defined(MBEDTLS_ECDH_C)

#define ECP_SECP256R1_KEY_SIZE 32

int ecies_encrypt(mbedtls_ecdh_context *ctx, uint8_t *in, uint32_t in_len, uint8_t *out,
					 uint32_t out_len)
{
	// TODO check if nonce can be zero as key is never used twice
	uint8_t nonce[12] = { 0x0 };
	uint32_t nonce_len = sizeof(nonce);

	int ret = -1;

	// Generate ECDH Shared Secret
	uint8_t shared[ECP_SECP256R1_KEY_SIZE];
	ret = ecdh_derive_secret(ctx, shared, sizeof(shared));
	if (ret != 0) {
		return ret;
	}

	uint8_t key[32];

	// Generate symmetric key from ECC shared secret via KDF
	ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, shared,
					   sizeof(shared), NULL, 0, key, sizeof(key));
	if (ret != 0) {
		return ret;
	}

	// Symmetrically encrypt the payload with AEAD
	chacha20_poly1305_encrypt(in, in_len, out, out_len, nonce, nonce_len, NULL, 0, key);
	if (ret != 0) {
		return ret;
	}

	return ret;
}

int ecies_decrypt(mbedtls_ecdh_context *ctx, uint8_t *in, uint32_t in_len, uint8_t *out,
					 uint32_t out_len)
{
	// TODO check if nonce can be zero as key is never used twice
	uint8_t nonce[12] = { 0x0 };
	uint32_t nonce_len = sizeof(nonce);

	int ret = -1;

	// Generate ECDH Shared Secret
	uint8_t shared[ECP_SECP256R1_KEY_SIZE];
	ret = ecdh_derive_secret(ctx, shared, sizeof(shared));
	if (ret != 0) {
		return ret;
	}

	uint8_t key[32];

	// Generate symmetric key from ECC shared secret via KDF
	ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, shared,
					   sizeof(shared), NULL, 0, key, sizeof(key));
	if (ret != 0) {
		return ret;
	}

	// Symmetrically decrypt the payload with AEAD
	ret = chacha20_poly1305_decrypt(in, in_len, out, out_len, nonce, nonce_len, NULL, 0, key);
	if (ret != 0) {
		return ret;
	}

	return ret;
}

#endif

#endif /* MBEDTLS_CONFIG_FILE */
