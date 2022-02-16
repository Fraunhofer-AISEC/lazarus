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
static LZ_RESULT lz_get_next_staging_slot(uint8_t **staging_slot, uint32_t size_req);

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
/**
 * Write the boot mode request for the next boot to the staging area
 * @param boot_mode_param The requested boot mode
 * @return
 */
LZ_RESULT lz_set_boot_mode_request(boot_mode_t boot_mode_param)
{
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

	// Write the page back to flash
	bool result =
		lz_flash_write_nse((void *)flash_start, (void *)overwrite_area, sizeof(overwrite_area));

	if (!result) {
		dbgprint(DBG_ERR,
				 "ERROR: Failed to flash boot mode request to staging area. "
				 "Function lz_flash_wire_nse returned %x\n",
				 result);
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

void lz_error_handler(void)
{
	dbgprint(DBG_ERR, "FATAL: Non-recoverable error. Device might need to be re-provisioned.\n");
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
 * Find the next free slot in the staging area and return its address
 *
 * @param staging_elem_slot The address of the next free slot that is returned
 * @param size_req The size of the requested slot including the header
 * @return LZ_SUCCESS, if a slot was found, otherwise LZ_ERROR
 */
static LZ_RESULT lz_get_next_staging_slot(uint8_t **staging_slot, uint32_t size_req)
{
	uint32_t staging_area_size = sizeof(lz_staging_area.content);
	uint32_t cursor = 0;
	LZ_RESULT result = LZ_ERROR;

	while (cursor < staging_area_size) {
		lz_auth_hdr_t *staging_elem_hdr =
			(lz_auth_hdr_t *)(((uint32_t)&lz_staging_area.content) + cursor);

		// If the header is invalid or there is no header at all, we can override it
		if (!(staging_elem_hdr->content.magic == LZ_MAGIC) ||
			(staging_elem_hdr->content.payload_size == 0) ||
			memcmp((void *)staging_elem_hdr->content.nonce,
				   (void *)lz_img_boot_params.info.next_nonce,
				   sizeof(staging_elem_hdr->content.nonce))) {
			// Check if the element fits into the staging area
			if (size_req < (staging_area_size - cursor)) {
				*staging_slot = (uint8_t *)staging_elem_hdr;
				dbgprint(DBG_VERB, "VERB: Found staging element slot at location: 0x%x\n",
						 staging_elem_hdr);

				result = LZ_SUCCESS;
				break;
			} else {
				result = LZ_ERROR;
				break;
			}
		}

		// Move cursor to next element
		cursor += (staging_elem_hdr->content.payload_size + sizeof(lz_auth_hdr_t));
	}

	// Staging area already filled, cannot find slot
	return result;
}

LZ_RESULT
lz_flash_staging_element(uint8_t *buf, uint32_t buf_size, uint32_t total_size, uint32_t pending)
{
	static uint8_t *start = NULL;
	LZ_RESULT result = LZ_ERROR;

	// Get next slot in staging area if a new firmware is to be flashed
	if (pending == total_size) {
		if (lz_get_next_staging_slot(&start, buf_size) != LZ_SUCCESS) {
			dbgprint(DBG_ERR, "ERROR: Could not find a place on staging area.\n");
			goto exit;
		}
	}

	dbgprint(DBG_VERB,
			 "Writing %d bytes (RAM Address 0x%x, total %d, pending %d) to flash address "
			 "0x%x\n",
			 buf_size, buf, total_size, pending, start);

	if (!(lz_flash_write_nse((void *)start, (void *)buf, buf_size))) {
		dbgprint(DBG_ERR, "ERROR: Failed to write staging element to flash.\n");
		goto exit;
	}

	start += buf_size;

	result = LZ_SUCCESS;

exit:
	return result;
}

/**
 * Get next valid staging header
 * @param hdr Address of a header that should be moved to the next header address
 * @return LZ_SUCCESS, if a header was found, LZ_ERROR if there was no valid header
 */
LZ_RESULT lz_get_next_staging_hdr(lz_auth_hdr_t **hdr)
{
	uint32_t staging_area_size = sizeof(lz_staging_area.content);
	uint32_t staging_elem_size;
	lz_auth_hdr_t *hdr_tmp = *hdr;
	uint8_t *next_header;

	// Current header must be inside staging area, properly aligned and size not zero
	if ((uint8_t *)hdr_tmp < (uint8_t *)&lz_staging_area.content ||
		(uint8_t *)hdr_tmp >
			(uint8_t *)(((uint32_t)&lz_staging_area.content) + staging_area_size) ||
		((uint32_t)hdr_tmp % FLASH_PAGE_SIZE) || (hdr_tmp->content.payload_size == 0)) {
		dbgprint(DBG_INFO, "INFO: Did not find another valid staging element (or not properly "
						   "aligned)\n");
		return LZ_ERROR;
	}

	// Move cursor by the total size of the current staging element plus added alignment
	staging_elem_size = hdr_tmp->content.payload_size + sizeof(lz_auth_hdr_t);
	next_header = ((uint8_t *)hdr_tmp) + staging_elem_size;

	dbgprint(DBG_VERB, "INFO: Next header at 0x%x\n", next_header);

	// See whether next header still fits within bounds of staging area
	if (next_header > (uint8_t *)(((uint32_t)&lz_staging_area.content) + staging_area_size) ||
		(((lz_auth_hdr_t *)next_header)->content.payload_size == 0)) {
		dbgprint(DBG_INFO, "INFO: Did not find another valid staging element (or out of "
						   "bounds)\n");
		return LZ_ERROR;
	}

	// Check sanity of header
	if (((lz_auth_hdr_t *)next_header)->content.magic != LZ_MAGIC) {
		dbgprint(DBG_INFO, "INFO: Did not find another valid staging element (no LZ_MAGIC "
						   "after current element)\n");
		return LZ_ERROR;
	}

	*hdr = (lz_auth_hdr_t *)next_header;
	dbgprint(DBG_VERB, "INFO: Set hdr pointer to 0x%x\n", hdr);

	return LZ_SUCCESS;
}

/**
 * Gets pointer to the specified staging element header, if the header is present
 * @param requested_elem_type The requested element type
 * @param return_hdr Pointer to the header, if found, otherwise NULL
 * @return LZ_SUCCESS if the staging element was found, otherwise LZ_ERROR or LZ_NOT_FOUND
 */
LZ_RESULT lz_get_staging_hdr(hdr_type_t hdr_type, lz_auth_hdr_t **return_hdr, uint8_t *nonce)
{
	uint32_t staging_area_size = sizeof(lz_staging_area.content);
	uint32_t staging_elem_size;
	uint32_t cursor = 0;
	uint8_t num_elements = 0;
	uint32_t result = LZ_ERROR;
	lz_auth_hdr_t *hdr;

	// Cursor holds the current position in the staging area
	while (cursor < staging_area_size) {
		hdr = (lz_auth_hdr_t *)(((uint32_t)&lz_staging_area.content) + cursor);
		staging_elem_size = 0;

		// Check whether header is sane
		if (hdr->content.magic != LZ_MAGIC) {
			dbgprint(DBG_INFO,
					 "INFO: Element type %s not present among the %u elements in "
					 "staging area.\n",
					 HDR_TYPE_STRING[hdr_type], num_elements);
			result = LZ_NOT_FOUND;
			goto Cleanup;
		}

		num_elements++;
		staging_elem_size = hdr->content.payload_size;

		// There must be at least 1 byte of payload
		if (staging_elem_size == 0) {
			dbgprint(DBG_ERR, "ERROR: Element %u in staging area corrupted (element size 0).\n",
					 num_elements);
			result = LZ_ERROR;
			goto Cleanup;
		}

		// But the payload must not exceed the remaining size of the staging area
		if (staging_elem_size > staging_area_size - cursor) {
			dbgprint(DBG_ERR,
					 "ERROR: Element %u in staging area corrupted (area size limit exceeded).\n",
					 num_elements);
			result = LZ_ERROR;
			goto Cleanup;
		}

		// Check whether nonce in header equals our current nonce
		if (memcmp(&(hdr->content.nonce), nonce, sizeof(hdr->content.nonce))) {
			dbgprint(DBG_WARN,
					 "WARNING: Nonce of staging element %u differs from current nonce, "
					 "skipping it.\n",
					 num_elements);
		} else {
			// Header seems to be in good state and belong to the current boot cycle, let's see whether it refers to the requested element type
			if (hdr_type == hdr->content.type) {
				dbgprint(DBG_INFO,
						 "INFO: Element %u in staging area matches searched element type %s.\n",
						 num_elements, HDR_TYPE_STRING[hdr_type]);

				*return_hdr = hdr;
				result = LZ_SUCCESS;
				return result;
			}
		}

		// Move the cursor to the next header
		cursor += (staging_elem_size + sizeof(lz_auth_hdr_t));
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
bool lz_check_update_size(lz_auth_hdr_t *staging_elem_hdr)
{
	uint32_t image_size = staging_elem_hdr->content.payload_size;
	bool retVal = true;

	switch (staging_elem_hdr->content.type) {
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
		retVal = (image_size <= (sizeof(lz_img_hdr_t) + LZ_APP_CODE_SIZE));
		break;
	default:
		dbgprint(DBG_ERR, "ERROR: Unknown update image type.\n");
		retVal = false;
	}
	return retVal;
}

void lz_print_img_info(const char *img_name, volatile lz_img_hdr_t *img_hdr)
{
	if (img_hdr) {
		char *date = asctime(gmtime((time_t *)&img_hdr->hdr.content.issue_time));
		date[24] = '\0';
		dbgprint(DBG_INFO,
				 "\n****************************************************"
				 "\n    %s"
				 "\n    Version %d.%d"
				 "\n    Issued (UTC): %s"
				 "\n****************************************************\n",
				 img_name, img_hdr->hdr.content.version >> 16,
				 img_hdr->hdr.content.version & 0x0000ffff, date);
	} else {
		dbgprint(DBG_INFO,
				 "\n****************************************************"
				 "\n    %s"
				 "\n****************************************************\n",
				 img_name);
	}
}
