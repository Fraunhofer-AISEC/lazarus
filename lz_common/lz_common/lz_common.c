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

#include <time.h>
#include <stdio.h>

#include "lz_common.h"
#include "lz_flash_handler.h"
#include "lzport_debug_output.h"
#include "lzport_memory.h"
#include "lzport_flash.h"

__attribute__((section(".LZ_DATA_STORE"))) volatile lz_data_store_t lz_data_store;
// Signed headers of the binaries (signed by Lazarus Provisioning)
__attribute__((section(".LZ_CORE_HDR"))) volatile lz_img_hdr_t lz_core_hdr;
__attribute__((section(".CP_HDR"))) volatile lz_img_hdr_t lz_cpatcher_hdr;
__attribute__((section(".UD_HDR"))) volatile lz_img_hdr_t lz_udownloader_hdr;
__attribute__((section(".APP_HDR"))) volatile lz_img_hdr_t lz_app_hdr;

// The staging area contains all data, such as updates, which are written by the UD/App and which need to be verified by the UM
__attribute__((section(".STAGING_AREA"))) volatile lz_staging_area_t lz_staging_area;

// On early boot, we read the Lazarus Core's boot parameters from SRAM2, called RAM_DATA in the linker script
// Before loading a subsequent layer, we write the next layers boot parameters to RAM_DATA as well
__attribute__((section(".RAM_DATA.Alias"))) volatile lz_img_boot_params_t lz_img_boot_params;
__attribute__((section(".RAM_DATA.Certs"))) volatile lz_img_cert_store_t lz_img_cert_store;

void lz_get_uuid(uint8_t uuid[LEN_UUID_V4_BIN])
{
	memcpy(uuid, (void *)&lz_img_boot_params.info.dev_uuid, LEN_UUID_V4_BIN);
}

LZ_RESULT lz_has_valid_boot_params(void)
{
	if ((lz_img_boot_params.info.magic == LZ_MAGIC) && (lz_img_cert_store.info.magic == LZ_MAGIC)) {
		return LZ_SUCCESS;
	} else {
		return LZ_ERROR;
	}
}

bool lz_dev_reassociation_necessary(void)
{
	return lz_img_boot_params.info.dev_reassociation_necessary;
}

bool lz_firmware_update_necessary(void)
{
	return lz_img_boot_params.info.firmware_update_necessary;
}

const uint8_t *lz_next_nonce(void)
{
	return (const uint8_t *)lz_img_boot_params.info.next_nonce;
}

const ecc_priv_key_pem_t *lz_alias_id_keypair_priv(void)
{
	return (const ecc_priv_key_pem_t *)&lz_img_boot_params.info.alias_id_keypair_priv;
}

/**
 * Write the boot mode request for the next boot to the staging area
 * @param boot_mode_param The requested boot mode
 * @return
 */
LZ_RESULT lz_set_boot_mode_request(boot_mode_t boot_mode_param)
{
	INFO("Setting boot mode request to %d\n", boot_mode_param);

	// Get pointer to last page of staging area
	uint8_t *flash_start =
		(uint8_t *)((uint32_t)&lz_staging_area) + sizeof(lz_staging_area_t) - FLASH_PAGE_SIZE;

	// Temporarily load last page to RAM and modify boot parameter word
	uint8_t overwrite_area[FLASH_PAGE_SIZE];
	uint32_t boot_mode = (uint32_t)boot_mode_param;

	// Copy last page of staging area into RAM
	memcpy(overwrite_area, flash_start, FLASH_PAGE_SIZE);

	// Overwrite last 4 byte with boot mode flag
	memcpy((uint8_t *)(((uint32_t)overwrite_area) + FLASH_PAGE_SIZE - sizeof(uint32_t)), &boot_mode,
		   sizeof(uint32_t));

	INFO("Writing flash @0x%x,  size 0x%x\n", (uint32_t)flash_start, sizeof(overwrite_area));

	// Write the page back to flash
	bool result =
		lz_flash_write_nse((void *)flash_start, (void *)overwrite_area, sizeof(overwrite_area));

	if (!result) {
		ERROR("Failed to flash boot mode request to staging area. "
			  "Function lz_flash_wire_nse returned %x\n",
			  result);
		return LZ_ERROR;
	}

	INFO("Successfully set boot mode request\n");

	return LZ_SUCCESS;
}

void lz_error_handler(void)
{
	ERROR("Non-recoverable error. Device might need to be re-provisioned.\n");
	for (;;)
		;
}

/**
 * Check if the specified memory area is all zero
 * @param start Start of the memory area
 * @param size Size of the memory area in bytes
 * @return true, if the memory is all zero, otherwise false
 */
bool lz_is_mem_zero(const void *start, uint32_t size)
{
	for (uint32_t n = 0; n < size; n++) {
		if (((uint8_t *)start)[n] != 0x00)
			return false;
	}
	return true;
}

/**
 * Get next valid staging header
 * @param hdr Address of a header that should be moved to the next header address
 * @return LZ_SUCCESS, if a header was found, LZ_ERROR if there was no valid header
 */
LZ_RESULT lz_get_next_staging_hdr(lz_staging_hdr_t **hdr)
{
	uint32_t staging_area_size = sizeof(lz_staging_area.content);
	uint32_t staging_elem_size;
	lz_staging_hdr_t *hdr_tmp = *hdr;
	uint8_t *next_header;

	// Current header must be inside staging area, properly aligned and size not zero
	if ((uint8_t *)hdr_tmp < (uint8_t *)&lz_staging_area.content ||
		(uint8_t *)hdr_tmp >
			(uint8_t *)(((uint32_t)&lz_staging_area.content) + staging_area_size) ||
		((uint32_t)hdr_tmp % FLASH_PAGE_SIZE) || (hdr_tmp->payload_size == 0)) {
		VERB("Did not find another valid staging element (or not properly "
			 "aligned)\n");
		return LZ_ERROR;
	}

	// Move cursor by the total size of the current staging element plus added alignment
	staging_elem_size = hdr_tmp->payload_size + sizeof(lz_staging_hdr_t);
	next_header = ((uint8_t *)hdr_tmp) + staging_elem_size;

	VERB("Next header at 0x%x\n", next_header);

	// See whether next header still fits within bounds of staging area
	if (next_header > (uint8_t *)(((uint32_t)&lz_staging_area.content) + staging_area_size) ||
		(((lz_staging_hdr_t *)next_header)->payload_size == 0)) {
		VERB("Did not find another valid staging element (or out of "
			 "bounds)\n");
		return LZ_ERROR;
	}

	// Check sanity of header
	if (((lz_staging_hdr_t *)next_header)->magic != LZ_MAGIC) {
		return LZ_ERROR;
	}

	*hdr = (lz_staging_hdr_t *)next_header;
	VERB("Set hdr pointer to 0x%x\n", hdr);

	return LZ_SUCCESS;
}

/**
 * Check if the payload's size in the staging area is valid.
 *
 * It will check if the payload size does not exceed the remaining size in
 * the staging area.
 */
LZ_RESULT lz_check_staging_payload_size(lz_staging_hdr_t *hdr, unsigned payload_size)
{
	uintptr_t start = (uintptr_t)&lz_staging_area.content;
	uintptr_t end = (uintptr_t)start + sizeof(lz_staging_area.content);
	uintptr_t hdr_start = (uintptr_t)hdr;
	uintptr_t hdr_end = (uintptr_t)hdr + sizeof(*hdr);

	if (hdr_start < start || hdr_start >= end)
		return LZ_ERROR;

	if (hdr_end < start || hdr_end >= end)
		return LZ_ERROR;

	// Don't calculate the address of the end of the payload and check it in
	// the same way. The calculation could lead to an arithmetic overflow.

	unsigned remaining = end - hdr_end;

	if (remaining < payload_size)
		return LZ_ERROR;

	return LZ_SUCCESS;
}

/**
 * Gets pointer to the specified staging element header, if the header is present
 * @param requested_elem_type The requested element type
 * @param return_hdr Pointer to the header, if found, otherwise NULL
 * @return LZ_SUCCESS if the staging element was found, otherwise LZ_ERROR or LZ_NOT_FOUND
 */
LZ_RESULT lz_get_staging_hdr(hdr_type_t hdr_type, lz_staging_hdr_t **return_hdr)
{
	uint32_t staging_area_size = sizeof(lz_staging_area.content);
	uint32_t staging_elem_size;
	uint32_t cursor = 0;
	uint8_t num_elements = 0;
	uint32_t result = LZ_ERROR;
	lz_staging_hdr_t *hdr;

	// Cursor holds the current position in the staging area
	while (cursor < staging_area_size) {
		hdr = (lz_staging_hdr_t *)(((uint32_t)&lz_staging_area.content) + cursor);
		staging_elem_size = 0;

		// Check whether header is sane
		if (hdr->magic != LZ_MAGIC) {
			INFO("Element type %s not present among the %u elements in "
				 "staging area.\n",
				 HDR_TYPE_STRING[hdr_type], num_elements);
			result = LZ_NOT_FOUND;
			goto Cleanup;
		}

		num_elements++;
		staging_elem_size = hdr->payload_size;

		// There must be at least 1 byte of payload
		if (staging_elem_size == 0) {
			ERROR("Element %u in staging area corrupted (element size 0).\n", num_elements);
			result = LZ_ERROR;
			goto Cleanup;
		}

		// But the payload must not exceed the remaining size of the staging area
		if (staging_elem_size > staging_area_size - cursor) {
			ERROR("Element %u in staging area corrupted (area size limit exceeded).\n",
				  num_elements);
			result = LZ_ERROR;
			goto Cleanup;
		}

		// Header seems to be in good state and belong to the current boot cycle, let's see whether it refers to the requested element type
		if (hdr_type == hdr->type) {
			INFO("Element %u in staging area matches searched element type %s.\n", num_elements,
				 HDR_TYPE_STRING[hdr_type]);

			*return_hdr = hdr;
			result = LZ_SUCCESS;
			return result;
		}

		// Move the cursor to the next header
		cursor += (staging_elem_size + sizeof(lz_staging_hdr_t));
	}

Cleanup:
	*return_hdr = NULL;
	return result;
}

/**
 * Check if the update does not exceed the maximum size in the flash
 * @param staging_elem_hdr Header of the update
 * @return True if the update fits, otherwise false
 */
bool lz_check_update_size(hdr_type_t type, unsigned image_size)
{
	bool retVal = true;

	switch (type) {
	case LZ_CORE_UPDATE:
		retVal = (image_size <= (sizeof(lz_img_hdr_t) + LZ_CORE_CODE_SIZE + LZ_CORE_NSC_SIZE));
		break;
	case LZ_UDOWNLOADER_UPDATE:
		retVal = (image_size <= (sizeof(lz_img_hdr_t) + LZ_UD_CODE_SIZE));
		break;
	case LZ_CPATCHER_UPDATE:
		retVal = (image_size <= (sizeof(lz_img_hdr_t) + LZ_CPATCHER_CODE_SIZE));
		break;
	case APP_UPDATE:
		retVal = (image_size <= (sizeof(lz_img_hdr_t) + LZ_APP_CODE_SIZE + LZ_APP_VULN_SIZE));
		break;
	default:
		ERROR("Unknown update image type.\n");
		retVal = false;
	}
	return retVal;
}

void lz_print_img_info(const char *img_name, volatile lz_img_hdr_t *img_hdr)
{
	if (img_hdr) {
		char *date = asctime(gmtime((time_t *)&img_hdr->hdr.content.issue_time));
		date[24] = '\0';
		INFO("\n****************************************************"
			 "\n    %s"
			 "\n    Version %d.%d"
			 "\n    Issued (UTC): %s"
			 "\n****************************************************\n",
			 img_name, img_hdr->hdr.content.version >> 16,
			 img_hdr->hdr.content.version & 0x0000ffff, date);
	} else {
		INFO("\n****************************************************"
			 "\n    %s"
			 "\n****************************************************\n",
			 img_name);
	}
}
