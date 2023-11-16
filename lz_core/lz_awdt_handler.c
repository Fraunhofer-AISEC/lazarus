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

#include "arm_cmse.h"
#include "lzport_debug_output.h"

#include "lzport_memory.h"
#include "lzport_rng.h"
#include "lzport_wdt.h"
#include "lz_common.h"
#include "lz_awdt.h"
#include "lz_core.h"
#include "lz_msg_decode.h"

#define MAX_STRING_LENGTH 0x400

static uint8_t active_nonce[LEN_NONCE] = { 0 };

bool lz_awdt_last_reset_awdt(void)
{
	return lzport_last_reset_awdt();
}

LZ_RESULT lz_awdt_init(uint32_t time_s)
{
	VERB("AWDT - Initializing random number generator\n");
	lzport_rng_init();

	VERB("AWDT - Initialializing Done!\n");
	lzport_wdt_init(time_s);

	return LZ_SUCCESS;
}

__attribute__((cmse_nonsecure_entry)) LZ_RESULT lz_awdt_get_nonce_nse(uint8_t *nonce)
{
	VERB("AWDT - Generating Nonce..\n");

	/* Check whether string is located in non-secure memory */
	if (cmse_check_address_range((void *)nonce, LEN_NONCE, CMSE_NONSECURE | CMSE_MPU_READ) ==
		NULL) {
		ERROR("\nAWDT Error: Nonce input buffer is not located in normal world!\n");
		return LZ_ERROR;
	}

	if (lzport_rng_get_random_data(nonce, LEN_NONCE) != 0) {
		ERROR("AWDT ERROR: Could not generate nonce\n");
		return LZ_ERROR;
	}

	VERB("AWDT - Nonce = ");
	for (uint8_t i = 0; i < LEN_NONCE; i++) {
		VERB("%02X ", nonce[i]);
	}
	VERB("\n");
	VERB("AWDT - Successfully generated nonce!\n");

	memcpy(active_nonce, nonce, LEN_NONCE);

	return LZ_SUCCESS;
}

static LZ_RESULT decode_and_check_awdt_message(uint8_t *buffer, size_t buffer_size,
											   uint32_t *time_ms)
{
	uint8_t nonce[LEN_NONCE];
	if (lz_msg_decode_awdt_refresh(buffer, buffer_size, time_ms, nonce) != LZ_SUCCESS) {
		ERROR("Failed to decode Awdt refresh response\n");
		return LZ_ERROR;
	}

	INFO("Got AWDT refresh message with time_ms=%d\n", (int)*time_ms);

	/* Nonce must match with input provided nonce */
	if (memcmp(nonce, active_nonce, sizeof(nonce))) {
		ERROR("Staging element's nonce incorrect\n");
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

__attribute__((cmse_nonsecure_entry)) LZ_RESULT lz_awdt_put_ticket_nse(uint8_t *buffer,
																	   size_t buffer_size)
{
	VERB("AWDT -Reloading with ticket_hdr\n");
	VERB("AWDT -Checking Address Range\n");

	/* Check whether string is located in non-secure memory */
	if (cmse_check_address_range((void *)buffer, buffer_size, CMSE_NONSECURE | CMSE_MPU_READ) ==
		NULL) {
		ERROR("AWDT - Input buffer is not located in normal world!\n");
		return LZ_ERROR;
	}

	uint32_t time_ms;
	if (decode_and_check_awdt_message(buffer, buffer_size, &time_ms) == LZ_SUCCESS) {
		VERB("AWDT - Signature successfully verified. Reloading Watchdog.."
			 "\n");

		lzport_wdt_reload(time_ms / 1000);

		VERB("AWDT - Reload Timer with new timeout: %dms!\n", time_ms);
	} else {
		ERROR("AWDT - Failed to verify signature. AWDT NOT RELOADED\n");
	}

	// Zero out nonce to avoid replay attacks
	secure_zero_memory(active_nonce, LEN_NONCE);

	return LZ_SUCCESS;
}
