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

#if defined(MBEDTLS_PK_WRITE_C)

#include "mbedtls/pk.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/hmac_drbg.h"

#include "ecc.h"

int lz_derive_ecc_keypair(lz_ecc_keypair *keypair, const void *seed, size_t seed_size)
{
	mbedtls_pk_init(keypair);
	mbedtls_hmac_drbg_context hmac_drbg_ctx;
	mbedtls_hmac_drbg_init(&hmac_drbg_ctx);
	int re;

	// Get hash algorithm
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (md_info == NULL) {
		dbgprint(DBG_INFO, "ERROR: Could not find hash algorithm\n");
		re = -1;
		goto clean;
	}

	// Initialize drgb context
	CHECK(mbedtls_hmac_drbg_seed_buf(&hmac_drbg_ctx, md_info, seed, seed_size),
		  "Error while initializing DRGB context");
	CHECK(mbedtls_pk_setup(keypair, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)),
		  "Error setting up public key context");
	CHECK(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*keypair),
							  mbedtls_hmac_drbg_random, &hmac_drbg_ctx),
		  "Could not derive ECC keypair");

clean:
	if (re < 0) {
		mbedtls_pk_free(keypair);
	}
	mbedtls_hmac_drbg_free(&hmac_drbg_ctx);

	return re;
}

#if defined(MBEDTLS_PEM_WRITE_C)
int lz_pub_key_to_pem(lz_ecc_keypair *keypair, lz_ecc_pub_key_pem *pem)
{
	int re = 0;

	// Writing the pubkey to the buffer
	CHECK(mbedtls_pk_write_pubkey_pem(keypair, (unsigned char *)pem->key, sizeof(pem->key)),
		  "Error writing pubkey (PEM)");

clean:
	return re;
}

int lz_priv_key_to_pem(lz_ecc_keypair *keypair, lz_ecc_priv_key_pem *pem)
{
	int re = 0;

	CHECK(mbedtls_pk_write_key_pem(keypair, (unsigned char *)pem->key, sizeof(pem->key)),
		  "Error writing pubkey (PEM)");

clean:
	return re;
}
#endif

#if defined(MBEDTLS_PK_PARSE_C)
int lz_pem_to_pub_key(lz_ecc_keypair *keypair, const lz_ecc_pub_key_pem *pem)
{
	mbedtls_pk_init(keypair);
	int re = 0;

	CHECK(mbedtls_pk_parse_public_key(keypair, (unsigned char *)pem->key,
									  strnlen(pem->key, MAX_PUB_ECP_PEM_BYTES - 1) + 1),
		  "Error parsing the public PEM key");

clean:
	if (re < 0) {
		mbedtls_pk_free(keypair);
	}
	return re;
}

int lz_pem_to_priv_key(lz_ecc_keypair *keypair, const lz_ecc_priv_key_pem *pem)
{
	mbedtls_pk_init(keypair);
	int re = 0;

	CHECK(mbedtls_pk_parse_key(keypair, (unsigned char *)pem->key, strlen(pem->key) + 1, NULL, 0),
		  "Error parsing the private PEM key");

clean:
	if (re < 0) {
		mbedtls_pk_free(keypair);
	}
	return re;
}
#endif

lz_ecc_private_key *lz_keypair_to_private(lz_ecc_keypair *keypair)
{
	return &mbedtls_pk_ec(*keypair)->d;
}

lz_ecc_public_key *lz_keypair_to_public(lz_ecc_keypair *keypair)
{
	return &mbedtls_pk_ec(*keypair)->Q;
}

int lz_compare_public_key(lz_ecc_public_key *k1, lz_ecc_public_key *k2)
{
	return mbedtls_ecp_point_cmp(k1, k2);
}

void lz_free_keypair(lz_ecc_keypair *keypair)
{
	mbedtls_pk_free(keypair);
}

#endif /* MBEDTLS_PK_WRITE_C_ */

#endif /* MBEDTLS_CONFIG_FILE */
