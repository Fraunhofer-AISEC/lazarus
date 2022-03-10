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

#include <stdio.h>
#include "fsl_iap.h"
#include "fsl_iap_ffr.h"

#include "lz_error.h"
#include "lz_common.h"
#include "lzport_flash.h"
#include "lzport_debug_output.h"

#define SECURE_BIT_MASK 0x10000000
#define min(x, y) ((x) < (y) ? (x) : (y))

static flash_config_t g_flash_config;

static void verify_status(status_t status);
static bool lzport_flash_program_page(uint32_t start, uint8_t *buf);

bool lzport_flash_init(void)
{
	status_t status;

	// Clean up Flash driver Structure
	memset(&g_flash_config, 0, sizeof(flash_config_t));

	// Initialize flash driver
	dbgprint(DBG_VERB, "Initializing flash driver...\n");
	status = FLASH_Init(&g_flash_config);
	verify_status(status);
	if (kStatus_Success == status) {
		return true;
	}

	return false;
}

void lzport_flash_get_properties(void)
{
	if (0 == g_flash_config.PFlashTotalSize) {
		dbgprint(DBG_ERR, "ERROR: Flash is not properly initialized\n");
		return;
	}

	uint32_t pflashBlockBase = 0;
	uint32_t pflashTotalSize = 0;
	uint32_t pflashSectorSize = 0;
	uint32_t PflashPageSize = 0;

	/* Get flash properties kFLASH_ApiEraseKey */
	FLASH_GetProperty(&g_flash_config, kFLASH_PropertyPflashBlockBaseAddr, &pflashBlockBase);
	FLASH_GetProperty(&g_flash_config, kFLASH_PropertyPflashSectorSize, &pflashSectorSize);
	FLASH_GetProperty(&g_flash_config, kFLASH_PropertyPflashTotalSize, &pflashTotalSize);
	FLASH_GetProperty(&g_flash_config, kFLASH_PropertyPflashPageSize, &PflashPageSize);

	// Print flash information
	dbgprint(DBG_VERB, "kFLASH_PropertyPflashBlockBaseAddr = 0x%X\n", pflashBlockBase);
	dbgprint(DBG_VERB, "kFLASH_PropertyPflashSectorSize = %d\n", pflashSectorSize);
	dbgprint(DBG_VERB, "kFLASH_PropertyPflashTotalSize = %d\n", pflashTotalSize);
	dbgprint(DBG_VERB, "kFLASH_PropertyPflashPageSize = 0x%X\n", PflashPageSize);
}

bool lzport_flash_write(uint32_t start, uint8_t *buf, uint32_t size)
{
	uint8_t tmp[FLASH_PAGE_SIZE];
	// The start of the flash to be written
	uint32_t flash_start = start & ~SECURE_BIT_MASK;
	// The cursor where to flash is set to the page start
	uint32_t cursor_flash = flash_start - (flash_start % FLASH_PAGE_SIZE);
	// Size of the flash between page start and the actual address to be written
	uint32_t size_before = (flash_start % FLASH_PAGE_SIZE);
	// If the block to be flashed does not exceed a single page, there is no
	// part of the last page to be flashed
	uint32_t size_last_page = ((flash_start + size) < (cursor_flash + FLASH_PAGE_SIZE)) ?
								  0 :
								  ((flash_start + size) % FLASH_PAGE_SIZE);
	uint32_t cursor_buf = 0;
	bool result = false;

	dbgprint(DBG_VERB, "INFO: Flashing %d bytes from address 0x%X to address 0x%X\n", size, buf,
			 flash_start);

	// Start address is not page aligned, or is aligned but smaller than one page:
	// we have to read the first page
	if (((flash_start % FLASH_PAGE_SIZE) != 0) || size < FLASH_PAGE_SIZE) {
		// Read flash page
		if (!lzport_flash_read(cursor_flash, tmp, FLASH_PAGE_SIZE)) {
			goto exit;
		}

		// Append own data to the first flash page
		memcpy(&tmp[size_before], buf, min(size, FLASH_PAGE_SIZE - size_before));

		// Flash first page
		dbgprint(DBG_VERB, "INFO: Flashing from 0x%X to 0x%X\n", cursor_flash,
				 cursor_flash + FLASH_PAGE_SIZE - 1);
		if (!lzport_flash_program_page(cursor_flash, tmp)) {
			goto exit;
		}

		// Set cursor to next page
		cursor_flash += FLASH_PAGE_SIZE;
		cursor_buf = FLASH_PAGE_SIZE - size_before;
	}

	// Flash while there is still at lest one full page left
	while ((cursor_flash + FLASH_PAGE_SIZE) <= (flash_start + size)) {
		dbgprint(DBG_VERB, "INFO: Flashing from 0x%X to 0x%X\n", cursor_flash,
				 cursor_flash + FLASH_PAGE_SIZE - 1);

		// Flash next pages
		if (!lzport_flash_program_page(cursor_flash, &buf[cursor_buf])) {
			goto exit;
		}

		cursor_flash += FLASH_PAGE_SIZE;
		cursor_buf += FLASH_PAGE_SIZE;
	}

	// If size is not aligned and there was more than one page to flash,
	// read the last page, insert the data and write it back
	if (size_last_page != 0) {
		// Read flash
		if (!lzport_flash_read(cursor_flash, tmp, FLASH_PAGE_SIZE)) {
			goto exit;
		}

		// Insert own data
		memcpy(tmp, &buf[cursor_buf], size_last_page);

		// Flash last page
		dbgprint(DBG_VERB, "INFO: Flashing from 0x%X to 0x%X\n", cursor_flash,
				 cursor_flash + FLASH_PAGE_SIZE - 1);
		if (!lzport_flash_program_page(cursor_flash, tmp)) {
			goto exit;
		}
	}

	result = true;

exit:
	return result;
}

bool lzport_flash_program_page(uint32_t start, uint8_t *buf)
{
	bool result = false;
	uint32_t failedAddr, failedData;
	uint32_t flash_start = start & ~SECURE_BIT_MASK;

	// Parameter check: Page-alignment and within flash bounds
	if (!((flash_start < (FLASH_BASE_ADDR + FLASH_SIZE)) && (flash_start % FLASH_PAGE_SIZE) == 0)) {
		dbgprint(DBG_ERR,
				 "ERROR: Failed to flash page. Address 0x%x outside of flash memory range"
				 "\n",
				 start);
		goto Cleanup;
	}

	// Erase the required area. We have NAND flash, so erasing writes 1's in order to make writes possible
	if (!lzport_flash_erase_page(flash_start)) {
		goto Cleanup;
	}

	// Flash the buffer and verify
	dbgprint(DBG_VERB, "INFO: Programming flash..\n");
	uint32_t status = FLASH_Program(&g_flash_config, flash_start, buf, FLASH_PAGE_SIZE);
	verify_status(status);
	if (kStatus_Success != status) {
		goto Cleanup;
	}

	dbgprint(DBG_VERB, "INFO: Verifying flash programming...\n");
	status = FLASH_VerifyProgram(&g_flash_config, flash_start, FLASH_PAGE_SIZE, buf, &failedAddr,
								 &failedData);
	verify_status(status);
	if (kStatus_Success == status) {
		result = true;
	}

Cleanup:
	return result;
}

bool lzport_flash_erase_page(uint32_t start)
{
	dbgprint(DBG_VERB, "INFO: Erasing flash...\n");

	bool result = false;

	if (0 == g_flash_config.PFlashTotalSize) {
		dbgprint(DBG_ERR, "ERROR: Flash is not properly initialized\n");
		result = false;
		goto Cleanup;
	}

	// Parameter check: Page-alignment and within flash bounds
	if (!((start < (FLASH_BASE_ADDR + FLASH_SIZE)) && (start % FLASH_PAGE_SIZE) == 0)) {
		dbgprint(DBG_ERR,
				 "ERROR: Failed to erase page: address 0x%x outside of flash memory "
				 "range or not pagewise aligned\n",
				 start);
		goto Cleanup;
	}

	// Erase the necessary pages
	uint32_t status = FLASH_Erase(&g_flash_config, start, FLASH_PAGE_SIZE, kFLASH_ApiEraseKey);
	verify_status(status);
	if (kStatus_Success != status) {
		goto Cleanup;
	}

	/* Verify if the given flash range is successfully erased. */
	dbgprint(DBG_VERB, "Verifying erase...\n");

	status = FLASH_VerifyErase(&g_flash_config, start, FLASH_PAGE_SIZE);
	verify_status(status);
	if (kStatus_Success == status) {
		result = true;
	}

Cleanup:
	return result;
}

bool lzport_flash_erase(uint32_t start, uint32_t size)
{
	uint32_t start_internal = start;
	for (uint32_t i = 0; i < size / FLASH_PAGE_SIZE; i++) {
		if (!lzport_flash_erase_page(start_internal)) {
			return false;
		}
		start_internal += FLASH_PAGE_SIZE;
	}
	return true;
}

bool lzport_flash_read(uint32_t addr, uint8_t *buffer, uint32_t size)
{
	uint32_t flash_addr = addr & ~SECURE_BIT_MASK;

	dbgprint(DBG_VERB, "INFO: FLASH - Reading from flash\n");

	if (flash_addr >= (FLASH_BASE_ADDR + FLASH_SIZE)) {
		dbgprint(DBG_ERR,
				 "ERROR: Failed to read flash: address range 0x%x-0x%x is outside of "
				 "flash memory region\n",
				 addr, addr + size);
		return false;
	}

	memcpy(buffer, (void *)addr, size);

	dbgprint(DBG_VERB, "INFO: FLASH - Successfully read %d bytes from location 0x%X\n", size, addr);
	return true;
}

int lzport_retrieve_uuid(uint8_t uuid[LEN_UUID_V4_BIN])
{
	if (FFR_Init(&g_flash_config) != kStatus_Success) {
		dbgprint(DBG_ERR, "ERROR: Failed to init FFR\n");
		return LZ_ERROR;
	}

	if (FFR_GetUUID(&g_flash_config, uuid) != kStatus_Success) {
		dbgprint(DBG_ERR, "ERROR: Failed to retrieve UUID from protected flash\n");
		return LZ_ERROR;
	}

	FFR_Lock_All(&g_flash_config);

	return LZ_SUCCESS;
}

/* ############################### Private function definitions #################################*/

void verify_status(status_t status)
{
	switch (status) {
	case kStatus_Success:
		dbgprint(DBG_VERB, "Flash status: Success\n\n");
		break;
	case kStatus_InvalidArgument:
		dbgprint(DBG_VERB, "Flash status: Invalid argument\n\n");
		break;
	case kStatus_FLASH_AddressError:
		dbgprint(DBG_VERB, "Flash status: Address error\n\n");
		break;
	case kStatus_FLASH_AlignmentError:
		dbgprint(DBG_VERB, "Flash status: Alignment Error\n\n");
		break;
	case kStatus_FLASH_AccessError:
		dbgprint(DBG_VERB, "Flash status: Access Error\n\n");
		break;
	case kStatus_FLASH_CommandNotSupported:
		dbgprint(DBG_VERB, "Flash status: This API is not supported in current target\n\n");
		break;
	case kStatus_FLASH_EccError:
		dbgprint(DBG_VERB, "Flash status: ECC Error\n");
		break;
	default:
		dbgprint(DBG_VERB, "Flash status: Other Error: 0x%X / %d\n\n", status, status);
		break;
	}
}
