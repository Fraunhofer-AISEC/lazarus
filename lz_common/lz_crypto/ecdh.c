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
#include <stdint.h>

#if defined(MBEDTLS_ECDH_C)

#include "mbedtls/ecdh.h"
#include "crypto_common.h"
#include "ecdh.h"

int ecdh_gen_key_pair(mbedtls_ecdh_context *ctx)
{
	int ret = -1;

	mbedtls_ecdh_init(ctx);

	ret = mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP256R1);
	if (ret != 0) {
		INFO("ERROR: Failed to initialize context - mbedtls_ecp_group_load returned "
			 "-0x%04x\n",
			 -ret);
		goto exit;
	}

	// This actually generates a key pair
	ret = mbedtls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q, crypto_rand, NULL);
	if (ret != 0) {
		ERROR("Failed to generate key-pair - mbedtls_ecdh_gen_public returned "
			  "-0x%04x\n",
			  ret);
		goto exit;
	}

exit:
	return ret;
}

int ecdh_export_pub(uint8_t *pub, size_t len, mbedtls_ecdh_context *ctx)
{
	if (len < ECP_SECP256R1_KEY_SIZE) {
		INFO("ERROR: Failed to export public key. Key size too small\n");
	}
	// Export the public key to a 32 byte (256 bits)
	int ret = mbedtls_mpi_write_binary(&ctx->Q.X, pub, ECP_SECP256R1_KEY_SIZE);
	if (ret != 0) {
		ERROR("Failed to generate key-pair - mbedtls_mpi_write_binary (pub)"
			  "returned -0x%04x\n",
			  -ret);
	}
	return ret;
}

int ecdh_derive_secret(mbedtls_ecdh_context *ctx, uint8_t *shared, uint32_t len)
{
	int ret = -1;

	if (len != 32) {
		INFO("ERROR: Failed to derive secret. Invalid shared secret len\n");
		return ret;
	}

	// Derive shared secret
	ret = mbedtls_ecdh_compute_shared(&ctx->grp, &ctx->z, &ctx->Qp, &ctx->d, crypto_rand, NULL);
	if (ret != 0) {
		ERROR("Failed to generate shared secret - mbedtls_ecdh_compute_shared "
			  "returned -0x%04x\n\n",
			  -ret);
		goto exit;
	}

	ret = mbedtls_mpi_write_binary(&ctx->z, shared, ECP_SECP256R1_KEY_SIZE);
	if (ret != 0) {
		ERROR("ERROR: Failed to generate shared secret - mbedtls_mpi_write_binary "
			  "returned -0x%04x\n\n",
			  -ret);
		goto exit;
	}

exit:
	return ret;
}

#endif

#endif /* MBEDTLS_CONFIG_FILE */
