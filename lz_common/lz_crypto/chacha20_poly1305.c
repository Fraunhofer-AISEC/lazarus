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
#include "lzport_debug_output.h"
#include "mbedtls/chachapoly.h"
#include "chacha20_poly1305.h"

#if defined(MBEDTLS_CHACHAPOLY_C)

#define AUTHTAG_LEN 16
#define NONCE_LEN 12
#define encrypted_len(plain_len) ((plain_len) + AUTHTAG_LEN)

int chacha20_poly1305_encrypt(const unsigned char *input, uint32_t input_len, unsigned char *output,
							  uint32_t output_len, uint8_t *nonce, size_t nonce_len,
							  const uint8_t *aad, size_t aad_len, uint8_t *key)
{
	int res;
	mbedtls_chachapoly_context ctx;

	// Check lengths
	if (encrypted_len(input_len) != output_len) {
		ERROR("Specified lengthts not correct (%d/%d)\n", input_len, output_len);
		return -1;
	}
	if (nonce_len != NONCE_LEN) {
		ERROR("Specified nonce length not correct (must be 12)\n");
		return -1;
	}

	mbedtls_chachapoly_init(&ctx);

	res = mbedtls_chachapoly_setkey(&ctx, key);
	if (res != 0) {
		ERROR("Failed to set chacha20-poly1305 key\r\n");
		return res;
	}

	// In our wrapper, the 16 byte authentication tag is appended to the encrypted output
	res = mbedtls_chachapoly_encrypt_and_tag(&ctx, input_len, nonce, aad, aad_len, input, output,
											 output + input_len);
	if (res != 0) {
		ERROR("Failed to encrypt with chacha20-poly1305\r\n");
		return res;
	}

	mbedtls_chachapoly_free(&ctx);

	return res;
}

int chacha20_poly1305_decrypt(const uint8_t *input, const uint32_t input_len, uint8_t *output,
							  const uint32_t output_len, uint8_t *nonce, size_t nonce_len,
							  const uint8_t *aad, size_t aad_len, uint8_t *key)
{
	int res;
	mbedtls_chachapoly_context ctx;

	// Check lengths
	if (input_len != encrypted_len(output_len)) {
		ERROR("Specified lengthts not correct (%d/%d)\n", input_len, output_len);
		return -1;
	}
	if (nonce_len != NONCE_LEN) {
		ERROR("Specified nonce length not correct (must be 12)\n");
		return -1;
	}

	res = mbedtls_chachapoly_setkey(&ctx, key);
	if (res != 0) {
		ERROR("Failed to set chacha20-poly1305 key\r\n");
		return res;
	}

	// In our wrapper, the 16 byte authentication tag is appended to the encrypted input
	res = mbedtls_chachapoly_auth_decrypt(&ctx, output_len, nonce, aad, aad_len, input + output_len,
										  input, output);
	if (res != 0) {
		ERROR("Failed to decrypt with chacha20-poly1305: -0x%x\r\n", -res);
		return res;
	}

	mbedtls_chachapoly_free(&ctx);

	return res;
}

#endif

#endif /* MBEDTLS_CONFIG_FILE */
