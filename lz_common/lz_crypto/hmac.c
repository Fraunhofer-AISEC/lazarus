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

#ifdef MBEDTLS_MD_C

#include "hmac.h"
#include "lz_common.h"
#include "mbedtls/md.h"

int hmac_sha256(uint8_t *result, const void *data, size_t dataSize, const uint8_t *key,
				   size_t keySize)
{
	if (keySize != SYM_KEY_LENGTH) {
		return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
	}

	const mbedtls_md_info_t *info_sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

	return mbedtls_md_hmac(info_sha256, key, keySize, data, dataSize, result);
}

#endif

#endif /* MBEDTLS_CONFIG_FILE */
