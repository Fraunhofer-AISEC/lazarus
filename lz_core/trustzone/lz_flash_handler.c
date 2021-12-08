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

#include "stdint.h"
#include "arm_cmse.h"
#include "fsl_common.h"
#include "lz_common/lz_common.h"
#include "lzport_debug_output/lzport_debug_output.h"
#include "lzport_flash/lzport_flash.h"
#include "lzport_memory/lzport_memory.h"
#include "lz_trustzone_handler/lz_flash_handler.h"
#include "lzport_throttle_timer.h"

#define PAGE_SIZE_BYTE 512
#define PAGES_COUNT (LZ_STAGING_AREA_SIZE / PAGE_SIZE_BYTE) + 2
#define DOS_PAGE_WRITE_THRESHOLD 1000
#define DOS_THROTTLING_TIME_S (24 * 60 * 60)
static uint8_t heat_map[PAGES_COUNT];

__attribute__((cmse_nonsecure_entry)) bool lz_flash_write_nse(void *dest, void *src, uint32_t size)
{
	dbgprint(DBG_VERB, "INFO: NSE Entry Point: Flashing..\n");

	// Check whether memory is located in non-secure memory
	if (cmse_check_address_range((void *)src, size, CMSE_NONSECURE | CMSE_MPU_READ) == NULL) {
		dbgprint(DBG_ERR, "ERROR: src buffer (0x%x-0x%x) is not located in normal world!\n",
				 (uint32_t)src, (uint32_t)src + size);
		return false;
	}
	if (cmse_check_address_range((void *)dest, size, CMSE_NONSECURE | CMSE_MPU_READ) == NULL) {
		dbgprint(DBG_ERR, "ERROR: dest buffer is not located in normal world!\n", (uint32_t)dest,
				 (uint32_t)dest + size);
		return false;
	}

	// check whether memory is located in staging area, which is the only area the non-trusted
	// applications may write to.
	// NOTE: Currently, only writes to the staging area are allowed.
	// If necessary, Writes to the whole untrusted flash area can be allowed.
	if (((uint32_t)dest < LZ_STAGING_AREA_START) ||
		(((uint32_t)dest + size) > LZ_STAGING_AREA_END + 4)) // TODO + 4 magic number
	{
		dbgprint(DBG_ERR, "ERROR: dest buffer 0x%x-0x%x is not located in staging area!\n",
				 (uint32_t)dest, (uint32_t)dest + size);
		return false;
	}

	// DoS protection against flash wear-out.
	if (lzport_throttle_timer_is_active()) {
		dbgprint(DBG_ERR, "ERROR: DoS protection enabled. Flash writes are currently throttled!\n");
		return false;
	}

	uint32_t first_page = (((uint32_t)dest) - LZ_STAGING_AREA_START) / PAGE_SIZE_BYTE;
	uint32_t last_page = (((uint32_t)dest + size) - LZ_STAGING_AREA_START) / PAGE_SIZE_BYTE;
	for (uint32_t i = first_page; i <= last_page; i++) {
		heat_map[i]++;
		if (heat_map[i] >= DOS_PAGE_WRITE_THRESHOLD) {
			lzport_throttle_timer_start(DOS_THROTTLING_TIME_S);
			memset(&heat_map, 0, sizeof(heat_map));
			dbgprint(DBG_ERR,
					 "ERROR: DoS protection enabled. Flash writes are currently throttled!\n");
			return false;
		}
	}

	return lzport_flash_write((uint32_t)dest, src, size);
}
