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
#include "lz_common.h"
#include "lzport_debug_output.h"
#include "lzport_flash.h"
#include "lzport_throttle_timer.h"

#define PAGE_SIZE_BYTE 512
#define PAGES_COUNT_STAGING (LZ_STAGING_AREA_SIZE / PAGE_SIZE_BYTE) + 2
#define PAGES_COUNT_APP (LZ_APP_CODE_SIZE / PAGE_SIZE_BYTE) + 2
#define DOS_PAGE_WRITE_THRESHOLD 100
#define DOS_THROTTLING_TIME_S (24 * 60 * 60)

struct allowed_region {
	uint32_t start;
	uint32_t end;
	uint8_t *heat_map;
	uint32_t heat_map_size;
};

static uint8_t heat_map_staging[PAGES_COUNT_STAGING];
static uint8_t heat_map_app[PAGES_COUNT_APP];

// NOTE: Currently, only writes to the staging area or the demo app code
// area are allowed.
// If necessary, writes to the whole untrusted flash area can be allowed.
static struct allowed_region allowed_regions[] = {
	// staging area
	{
		.start = LZ_STAGING_AREA_START,
		.end = LZ_STAGING_AREA_START + LZ_STAGING_AREA_SIZE,
		.heat_map = heat_map_staging,
		.heat_map_size = sizeof(heat_map_staging),
	},
	// demo app code
	{
		.start = LZ_APP_CODE_START,
		.end = LZ_APP_CODE_START + LZ_APP_CODE_SIZE,
		.heat_map = heat_map_app,
		.heat_map_size = sizeof(heat_map_app),
	},
};

static bool is_inside_memory_region(const struct allowed_region *region, uint32_t dest,
									uint32_t size)
{
	return (dest >= region->start) && (dest + size <= region->end);
}

static bool check_memory_region(uint32_t dest, uint32_t size)
{
	// check whether memory is located in an allowed flash area,
	// which is the only area the non-trusted applications may write to.
	bool ok = false;
	for (int i = 0; i < sizeof(allowed_regions) / sizeof(allowed_regions[0]); i++) {
		const struct allowed_region *region = &allowed_regions[i];
		ok |= is_inside_memory_region(region, dest, size);
	}

	if (!ok) {
		ERROR(
			"ERROR: dest buffer 0x%x-0x%x is not located in staging area nor in demo app code area!\n",
			dest, dest + size);
	}
	return ok;
}

static bool update_single_heat_map(struct allowed_region *region, uint32_t dest, uint32_t size)
{
	uint32_t first_page = (dest - region->start) / PAGE_SIZE_BYTE;
	uint32_t last_page = ((dest + size) - region->start) / PAGE_SIZE_BYTE;
	for (uint32_t i = first_page; i <= last_page; i++) {
		region->heat_map[i]++;
		if (region->heat_map[i] >= DOS_PAGE_WRITE_THRESHOLD) {
			lzport_throttle_timer_start(DOS_THROTTLING_TIME_S);
			memset(region->heat_map, 0, region->heat_map_size);
			ERROR("DoS protection enabled. Flash writes are currently throttled!\n");
			return false;
		}
	}
	return true;
}

static bool update_heat_map(uint32_t dest, uint32_t size)
{
	for (int i = 0; i < sizeof(allowed_regions) / sizeof(allowed_regions[0]); i++) {
		struct allowed_region *region = &allowed_regions[i];
		if (is_inside_memory_region(region, dest, size))
			if (!update_single_heat_map(region, dest, size))
				return false;
	}
	return true;
}

__attribute__((cmse_nonsecure_entry)) bool lz_flash_write_nse(void *dest, void *src, uint32_t size)
{
	VERB("NSE Entry Point: Flashing..\n");

	// Check whether memory is located in non-secure memory
	if (cmse_check_address_range((void *)src, size, CMSE_NONSECURE | CMSE_MPU_READ) == NULL) {
		ERROR("src buffer (0x%x-0x%x) is not located in normal world!\n", (uint32_t)src,
			  (uint32_t)src + size);
		return false;
	}
	if (cmse_check_address_range((void *)dest, size, CMSE_NONSECURE | CMSE_MPU_READ) == NULL) {
		ERROR("dest buffer is not located in normal world!\n", (uint32_t)dest,
			  (uint32_t)dest + size);
		return false;
	}

	if (!check_memory_region((uint32_t)dest, size))
		return false;

	// DoS protection against flash wear-out.
	if (lzport_throttle_timer_is_active()) {
		ERROR("DoS protection enabled. Flash writes are currently throttled!\n");
		return false;
	}

	if (!update_heat_map((uint32_t)dest, size))
		return false;

	return lzport_flash_write((uint32_t)dest, src, size);
}
