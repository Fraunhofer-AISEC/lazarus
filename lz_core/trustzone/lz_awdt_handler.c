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
#include "lzport_debug_output/lzport_debug_output.h"
#include "pin_mux.h"

#include "lzport_memory/lzport_memory.h"
#include "lzport_rng/lzport_rng.h"
#include "lzport_wdt.h"
#include "lz_common/lz_common.h"
#include "lz_trustzone_handler/lz_flash_handler.h"
#include "lz_awdt.h"
#include "lz_core.h"

#define MAX_STRING_LENGTH 0x400

static uint8_t active_nonce[LEN_NONCE] = { 0 };

bool lz_awdt_last_reset_awdt(void)
{
	return lzport_last_reset_awdt();
}

LZ_RESULT lz_awdt_init(uint32_t time_s)
{
	dbgprint(DBG_AWDT, "INFO: AWDT - Initializing random number generator\n");
	lzport_rng_init();

	dbgprint(DBG_AWDT, "INFO: AWDT - Initialializing Done!\n");
	lzport_wdt_init(time_s);

	return LZ_SUCCESS;
}

__attribute__((cmse_nonsecure_entry)) LZ_RESULT lz_awdt_get_nonce_nse(uint8_t *nonce)
{
	dbgprint(DBG_AWDT, "INFO: AWDT - Generating Nonce..\n");

	/* Check whether string is located in non-secure memory */
	if (cmse_check_address_range((void *)nonce, LEN_NONCE, CMSE_NONSECURE | CMSE_MPU_READ) ==
		NULL) {
		dbgprint(DBG_ERR, "\nAWDT Error: Nonce input buffer is not located in normal world!\n");
		return LZ_ERROR;
	}

	if (lzport_rng_get_random_data(nonce, LEN_NONCE) != 0) {
		dbgprint(DBG_ERR, "AWDT ERROR: Could not generate nonce\n");
		return LZ_ERROR;
	}

	dbgprint(DBG_AWDT, "INFO: AWDT - Nonce = ");
	for (uint8_t i = 0; i < LEN_NONCE; i++) {
		dbgprint(DBG_AWDT, "%02X ", nonce[i]);
	}
	dbgprint(DBG_AWDT, "\n");
	dbgprint(DBG_AWDT, "INFO: AWDT - Successfully generated nonce!\n");

	memcpy(active_nonce, nonce, LEN_NONCE);

	return LZ_SUCCESS;
}

__attribute__((cmse_nonsecure_entry)) LZ_RESULT lz_awdt_put_ticket_nse(lz_auth_hdr_t *ticket_hdr,
																	   uint32_t time_ms)
{
	dbgprint(DBG_AWDT, "INFO: AWDT -Reloading with ticket_hdr\n");
	dbgprint(DBG_AWDT, "INFO: AWDT -Checking Address Range\n");

	/* Check whether string is located in non-secure memory */
	if (cmse_check_address_range((void *)ticket_hdr, sizeof(lz_auth_hdr_t),
								 CMSE_NONSECURE | CMSE_MPU_READ) == NULL) {
		dbgprint(DBG_ERR, "ERROR: AWDT - Input buffer is not located in normal world!\n");
		return LZ_ERROR;
	}

	dbgprint(DBG_AWDT, "INFO: AWDT - Importing ECC Signature..\n");

	if (lz_core_verify_staging_elem_hdr(ticket_hdr, (uint8_t *)&time_ms, active_nonce) ==
		LZ_SUCCESS) {
		dbgprint(DBG_AWDT, "INFO: AWDT - Signature successfully verified. Reloading Watchdog.."
						   "\n");

		lzport_wdt_reload(time_ms / 1000);

		dbgprint(DBG_AWDT, "INFO: AWDT - Reload Timer with new timeout: %dms!\n", time_ms);
	} else {
		dbgprint(DBG_ERR, "ERROR: AWDT - Failed to verify signature. AWDT NOT RELOADED\n");
		return LZ_ERROR;
	}

	// Zero out nonce to avoid replay attacks
	secure_zero_memory(active_nonce, LEN_NONCE);

	return LZ_SUCCESS;
}
