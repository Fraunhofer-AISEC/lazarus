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

#include <stdint.h>
#include "lz_config.h"
#include "lz_common.h"
#include "lzport_debug_output.h"
#include "lzport_flash.h"
#include "exception_handler.h"

static LZ_RESULT lz_apply_core_update(void);
static LZ_RESULT lz_flash_core_update(lz_staging_hdr_t *staging_elem_hdr);

void lz_core_patcher_run(void)
{
	// Check whether Lazarus Core provided valid boot params
	if (lz_has_valid_boot_params() != LZ_SUCCESS) {
		ERROR("PANIC: Corrupted boot parameters.\n");
		lz_error_handler();
	}

	INFO("Applying Lazarus Core Update..\n");

	LZ_RESULT result = lz_apply_core_update();

	if (result == LZ_SUCCESS) {
		INFO("Successfully updated Lazarus Core. Rebooting..\n");
	} else {
		ERROR("Failed to update Lazarus Core. Rebooting..\n");
	}

	svc_reset_system();
}

static LZ_RESULT lz_apply_core_update(void)
{
	lz_staging_hdr_t *hdr;
	LZ_RESULT result = LZ_ERROR;

	if ((result = lz_get_staging_hdr(LZ_CORE_UPDATE, &hdr)) != LZ_SUCCESS) {
		WARN("Could not find Lazarus Core Update. Abort..\n");
		goto exit;
	}

	if ((result = lz_flash_core_update(hdr)) != LZ_SUCCESS) {
		WARN("Could not apply Lazarus Core Update. Abort..\n");
		goto exit;
	}

exit:
	return result;
}

/**
 * Apply the Lazarus Core update from the staging area to the Lazarus Core region
 * @param staging_elem_hdr
 * @return
 */
static LZ_RESULT lz_flash_core_update(lz_staging_hdr_t *staging_elem_hdr)
{
	uint8_t *staged_image_start;
	uint32_t payload_size = staging_elem_hdr->payload_size - staging_elem_hdr->msg_size;

	// Check whether the update fits into the image bounds
	if (!lz_check_update_size(staging_elem_hdr->type, payload_size)) {
		ERROR("Update image size exceeds bounds.\n");
		return LZ_ERROR_INVALID_HDR;
	}

	// Determine the start address of the update
	staged_image_start = (uint8_t *)(((uint32_t)staging_elem_hdr) + sizeof(lz_staging_hdr_t));

	// The real payload (i.e. the image) is appended to a message (e.g. protobuf)
	staged_image_start += staging_elem_hdr->msg_size;

	// Finally, flash the staged update, assuming that it is contiguous and in its full length on staging area
	INFO("Flashing staged update from staging area (0x%x) to update area (0x%x)\n",
		 (uint32_t)staged_image_start, LZ_CORE_HEADER_START);
	if (!(lzport_flash_write(LZ_CORE_HEADER_START, staged_image_start, payload_size))) {
		ERROR("lzport_flash_write failed.\n");
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}
