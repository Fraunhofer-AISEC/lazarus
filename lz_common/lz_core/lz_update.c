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
#include "fsl_common.h"
#include "lz_common.h"
#include "lzport_flash.h"
#include "lzport_memory.h"
#include "lzport_debug_output.h"
#include "lz_core.h"

static bool lz_staging_hdr_is_img_update(lz_auth_hdr_t *staging_elem_hdr);
static LZ_RESULT lz_apply_single_update(lz_auth_hdr_t *staging_elem_hdr);
static LZ_RESULT lz_get_img_meta(lz_auth_hdr_t *staging_elem_hdr, const lz_img_meta_t **img_meta);
static LZ_RESULT lz_apply_config_update(lz_auth_hdr_t *staging_elem_hdr);
static LZ_RESULT lz_apply_certs_update(lz_auth_hdr_t *staging_elem_hdr);
static LZ_RESULT lz_apply_img_update(lz_auth_hdr_t *staging_elem_hdr);
static LZ_RESULT lz_verify_img_hdr(lz_auth_hdr_t *staging_elem_hdr);

/**
 * Standard updates are all updates except Lazarus Core Update
 * @return
 */
LZ_RESULT lz_std_updates_pending(void)
{
	if ((lz_has_staging_elem_type(LZ_UDOWNLOADER_UPDATE) == LZ_SUCCESS) ||
		(lz_has_staging_elem_type(LZ_CPATCHER_UPDATE) == LZ_SUCCESS) ||
		(lz_has_staging_elem_type(APP_UPDATE) == LZ_SUCCESS) ||
		(lz_has_staging_elem_type(DEVICE_ID_REASSOC_RES) == LZ_SUCCESS) ||
		(lz_has_staging_elem_type(CONFIG_UPDATE) == LZ_SUCCESS)) {
		return LZ_SUCCESS;
	}

	return LZ_NOT_FOUND;
}

LZ_RESULT lz_verified_core_update_pending(void)
{
	lz_auth_hdr_t *staging_hdr = NULL;

	uint8_t nonce[LEN_NONCE];
	lz_get_curr_nonce(nonce);

	if (lz_get_staging_hdr(LZ_CORE_UPDATE, &staging_hdr, nonce) != LZ_SUCCESS) {
		return LZ_NOT_FOUND;
	}

	if (lz_verify_staging_header(staging_hdr, (((uint8_t *)staging_hdr) + sizeof(lz_auth_hdr_t))) !=
		LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Update staging header verificytion failed\n");
		return LZ_ERROR;
	}

	if (lz_verify_img_hdr(staging_hdr) != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Update image header verification failed\n");
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

LZ_RESULT lz_apply_updates(void)
{
	lz_auth_hdr_t *staging_elem_hdr = (lz_auth_hdr_t *)&lz_staging_area.content;
	uint32_t applied_updates = 0;
	LZ_RESULT result = LZ_ERROR;

	do {
		dbgprint(DBG_INFO, "INFO: Verifying staging element header at 0x%x\n", staging_elem_hdr);

		// UM uses cur_nonce provided by Lazarus Core to verify staging elements
		if (lz_verify_staging_header(staging_elem_hdr, (((uint8_t *)staging_elem_hdr) +
														sizeof(lz_auth_hdr_t))) == LZ_SUCCESS) {
			// For image updates, we must check their code signature based on their image header
			if (lz_staging_hdr_is_img_update(staging_elem_hdr)) {
				if (lz_verify_img_hdr(staging_elem_hdr) != LZ_SUCCESS) {
					dbgprint(DBG_ERR, "ERROR: Failed to verify update image header\n");
					result = LZ_ERROR;
					goto exit;
				}
			}

			// For cert/config updates, we are ready to apply it
			if (lz_apply_single_update(staging_elem_hdr) != LZ_SUCCESS) {
				dbgprint(DBG_ERR, "ERROR: Abort, installation of an update failed.\n");
				result = LZ_ERROR;
				goto exit;
			}

			applied_updates++;
		}
	} while (lz_get_next_staging_hdr(&staging_elem_hdr) == LZ_SUCCESS);

	result = LZ_SUCCESS;

exit:

	dbgprint(DBG_INFO, "INFO: Applied %d updated\n", applied_updates);
	return result;
}

LZ_RESULT lz_update_img_meta_data(void)
{
	lz_config_data_t config_data_cpy;
	bool flash_required = false;

	// Config data must be copied from flash to RAM in order to modify it
	memcpy(&config_data_cpy, (void *)&lz_data_store.config_data, sizeof(config_data_cpy));

	dbgprint(DBG_INFO, "INFO: Checking image meta data..\n");

	// Check if Lazarus Core meta data must be updated
	if ((config_data_cpy.img_info.rc_meta.last_issue_time != lz_core_hdr.hdr.content.issue_time) ||
		(config_data_cpy.img_info.rc_meta.lastVersion != lz_core_hdr.hdr.content.version) ||
		(config_data_cpy.img_info.rc_meta.magic != LZ_MAGIC)) {
		flash_required = true;
		config_data_cpy.img_info.rc_meta.last_issue_time = lz_core_hdr.hdr.content.issue_time;
		config_data_cpy.img_info.rc_meta.lastVersion = lz_core_hdr.hdr.content.version;
		config_data_cpy.img_info.rc_meta.magic = LZ_MAGIC;
		dbgprint(DBG_INFO, "INFO: Lazarus Core meta data will be updated in flash\n");
	}

	// Check if Update Manager meta data must be updated
	if ((config_data_cpy.img_info.um_meta.last_issue_time !=
		 lz_cpatcher_hdr.hdr.content.issue_time) ||
		(config_data_cpy.img_info.um_meta.lastVersion != lz_cpatcher_hdr.hdr.content.version) ||
		(config_data_cpy.img_info.um_meta.magic != LZ_MAGIC)) {
		flash_required = true;
		config_data_cpy.img_info.um_meta.last_issue_time = lz_cpatcher_hdr.hdr.content.issue_time;
		config_data_cpy.img_info.um_meta.lastVersion = lz_cpatcher_hdr.hdr.content.version;
		config_data_cpy.img_info.um_meta.magic = LZ_MAGIC;
		dbgprint(DBG_INFO, "INFO: Update Manager meta data will be updated in flash\n");
	}

	// Check if Update Downloader meta data must be updated
	if ((config_data_cpy.img_info.ud_meta.last_issue_time !=
		 lz_udownloader_hdr.hdr.content.issue_time) ||
		(config_data_cpy.img_info.ud_meta.lastVersion != lz_udownloader_hdr.hdr.content.version) ||
		(config_data_cpy.img_info.ud_meta.magic != LZ_MAGIC)) {
		flash_required = true;
		config_data_cpy.img_info.ud_meta.last_issue_time =
			lz_udownloader_hdr.hdr.content.issue_time;
		config_data_cpy.img_info.ud_meta.lastVersion = lz_udownloader_hdr.hdr.content.version;
		config_data_cpy.img_info.ud_meta.magic = LZ_MAGIC;
		dbgprint(DBG_INFO, "INFO: Update Downloader meta data will be updated in flash\n");
	}

	// Check if App meta data must be updated
	if ((config_data_cpy.img_info.app_meta.last_issue_time != lz_app_hdr.hdr.content.issue_time) ||
		(config_data_cpy.img_info.app_meta.lastVersion != lz_app_hdr.hdr.content.version) ||
		(config_data_cpy.img_info.app_meta.magic != LZ_MAGIC)) {
		flash_required = true;
		config_data_cpy.img_info.app_meta.last_issue_time = lz_app_hdr.hdr.content.issue_time;
		config_data_cpy.img_info.app_meta.lastVersion = lz_app_hdr.hdr.content.version;
		config_data_cpy.img_info.app_meta.magic = LZ_MAGIC;
		dbgprint(DBG_INFO, "INFO: App meta data will be updated in flash\n");
	}

	if (flash_required) {
		// Write the updated data to flash
		if (!(lzport_flash_write((uint32_t)&lz_data_store.config_data, (void *)&config_data_cpy,
								 sizeof(lz_data_store.config_data)))) {
			dbgprint(DBG_ERR, "ERROR: Failed to flash meta data\n");
			return LZ_ERROR;
		}
	} else {
		dbgprint(DBG_INFO, "INFO: No update of meta data required\n");
	}

	return LZ_SUCCESS;
}

/*****************************
 * Static Function Definitions
 *****************************/

/**
 * Check whether a staging element header is an image update. Does not perform any verification
 * on the header
 * @param staging_elem_hdr The staging header to be checked
 * @return True, when the staging header is an image update, otherwise false
 */
static bool lz_staging_hdr_is_img_update(lz_auth_hdr_t *staging_elem_hdr)
{
	return ((staging_elem_hdr->content.type == LZ_CORE_UPDATE) ||
			(staging_elem_hdr->content.type == LZ_UDOWNLOADER_UPDATE) ||
			(staging_elem_hdr->content.type == LZ_CPATCHER_UPDATE) ||
			(staging_elem_hdr->content.type == APP_UPDATE));
}

static LZ_RESULT lz_apply_single_update(lz_auth_hdr_t *staging_elem_hdr)
{
	if ((staging_elem_hdr->content.type == LZ_UDOWNLOADER_UPDATE) ||
		(staging_elem_hdr->content.type == LZ_CPATCHER_UPDATE) ||
		(staging_elem_hdr->content.type == APP_UPDATE)) {
		return lz_apply_img_update(staging_elem_hdr);
	} else if (staging_elem_hdr->content.type == DEVICE_ID_REASSOC_RES) {
		return lz_apply_certs_update(staging_elem_hdr);
	} else if (staging_elem_hdr->content.type == CONFIG_UPDATE) {
		return lz_apply_config_update(staging_elem_hdr);
	} else {
		dbgprint(DBG_ERR, "ERROR: Element type not an update.\n");
		return LZ_ERROR;
	}
}

/**
 * Apply a certificate update to the trust anchors of the device. The backend must create a
 * trust anchors structure and zero all elements that should not be updated in order to allow
 * partial updates
 * @param staging_elem_hdr
 * @return
 */
static LZ_RESULT lz_apply_certs_update(lz_auth_hdr_t *staging_elem_hdr)
{
	trust_anchors_t ta_copy = { 0 };
	trust_anchors_t *ta_update;
	bool device_cert_contained, device_issuer_cert_contained;

	// Size of payload must equal to TRUST_ANCHOR structure
	if (sizeof(ta_copy) != (staging_elem_hdr->content.payload_size)) {
		dbgprint(DBG_ERR,
				 "ERROR: Certs update size does not match size of TRUST_ANCHORS structure.\n");
		return LZ_ERROR;
	}

	// Copy current trust anchors data structure to RAM, overwrite and flash back
	memcpy((void *)&ta_copy, (void *)&lz_data_store.trust_anchors, sizeof(ta_copy));

	ta_update = (trust_anchors_t *)(((uint32_t)staging_elem_hdr) + sizeof(lz_auth_hdr_t));

	dbgprint(DBG_INFO, "INFO: Processing the contents of the TRUST_ANCHORS update...\n");

	// Not allowed: DeviceID pubkey updates, because this key originates from the device
	// if (!lz_is_mem_zero(&(ta_update->info.devicePubKey), sizeof(ta_update->info.devicePubKey)))
	if (!lz_is_mem_zero(&(ta_update->info.dev_pub_key), sizeof(ta_update->info.dev_pub_key))) {
		dbgprint(DBG_ERR, "ERROR: Device pub key cannot be remotely updated.\n");
		return LZ_ERROR;
	}

	// Check whether we need to update the code signing pubkey
	// if (!lz_is_mem_zero(&(ta_update->info.codeAuthPubKey), sizeof(ta_update->info.codeAuthPubKey)))
	if (!lz_is_mem_zero(&(ta_update->info.code_auth_pub_key),
						sizeof(ta_update->info.code_auth_pub_key))) {
		dbgprint(DBG_INFO, "INFO: Will update code signing public key.\n");
		// memcpy(&ta_copy.info.codeAuthPubKey, &(ta_update->info.codeAuthPubKey), sizeof(ta_copy.info.codeAuthPubKey));
		memcpy(&ta_copy.info.code_auth_pub_key, &(ta_update->info.code_auth_pub_key),
			   sizeof(ta_copy.info.code_auth_pub_key));
	}

	// Check if we need to update the backend pubkey
	if (!lz_is_mem_zero(&(ta_update->info.management_pub_key),
						sizeof(ta_update->info.management_pub_key))) {
		dbgprint(DBG_INFO, "INFO: Will update backend public key.\n");
		memcpy(&ta_copy.info.management_pub_key, &(ta_update->info.management_pub_key),
			   sizeof(ta_copy.info.management_pub_key));
	}

	device_cert_contained = (ta_update->info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size > 0);
	device_issuer_cert_contained = (ta_update->info.certTable[INDEX_LZ_CERTSTORE_HUB].size > 0);

	if (device_cert_contained && device_issuer_cert_contained) {
		dbgprint(DBG_INFO, "INFO: Will both update issuer/root cert and DeviceID cert.\n");

		memcpy(&ta_copy.info.certTable, &(ta_update->info.certTable),
			   sizeof(ta_copy.info.certTable));
		ta_copy.info.cursor = ta_update->info.cursor;
		memcpy(&ta_copy.certBag, &(ta_update->certBag), sizeof(ta_copy.certBag));
	} else if (device_cert_contained) {
		dbgprint(DBG_INFO, "INFO: Will update device certificate.\n");

		// Check whether the cert has the same size
		if (ta_update->info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size ==
			ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size) {
			// If so, then just overwrite and we're done
			memcpy(
				&ta_copy.certBag[ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].start],
				&(ta_update->certBag[ta_update->info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].start]),
				ta_update->info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size);
		}
		// Having a different size, we have to adapt start/size/cursor, and maybe also move certBag contents...
		else {
			// Element to be replaced larger than before?
			if (ta_update->info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size >
				ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size) {
				// If so, check whether updating it exceeds the certbag: Check current cursor and size difference to see if we hit the limit
				if (ta_copy.info.cursor +
						(ta_update->info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size -
						 ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size) >
					sizeof(ta_copy.certBag)) {
					dbgprint(
						DBG_ERR,
						"ERROR: DeviceID cert to be updated is larger than old one and would exceed certBag size.\n");
					return LZ_ERROR;
				}
			}

			// Overwrite DeviceID cert with new-sized DeviceID cert
			memcpy(
				&ta_copy.certBag[ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].start],
				&(ta_update->certBag[ta_update->info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].start]),
				ta_update->info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size);
			// Set size metadata. Start remains the same
			ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size =
				ta_update->info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size;
			// Adapt cursor
			ta_copy.info.cursor = ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].start +
								  ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size;
			// And write 0 byte after the cert
			ta_copy.certBag[ta_copy.info.cursor++] = '\0';

			// If device cert was originally located after root cert, we are done right now
			// If device cert was originally located before root cert, we have to relocate the issuer/root cert in the bag and correct the cursor
			if (ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].start <
				ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].start) {
				// Set new start position (size remains the same)
				ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].start = ta_copy.info.cursor;
				// Copy root cert from flash to update-copy (we did not update the issuer/root cert in this case here)
				memcpy(
					(void *)&ta_copy.certBag[ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].start],
					(void *)&(
						lz_data_store.trust_anchors.certBag[lz_data_store.trust_anchors.info
																.certTable[INDEX_LZ_CERTSTORE_HUB]
																.start]),
					ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].size);
				// Move cursor according to issuer/root cert size
				ta_copy.info.cursor += ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].size;
				// And write 0 byte after issuer/root cert
				ta_copy.certBag[ta_copy.info.cursor++] = '\0';
			}
		}
	}
	// Only DeviceID CA cert contained
	else if (device_issuer_cert_contained) {
		dbgprint(DBG_INFO, "INFO: Will device issuer root certificate.\n");

		if (ta_update->info.certTable[INDEX_LZ_CERTSTORE_HUB].size ==
			ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].size) {
			memcpy(&ta_copy.certBag[ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].start],
				   &(ta_update->certBag[ta_update->info.certTable[INDEX_LZ_CERTSTORE_HUB].start]),
				   ta_update->info.certTable[INDEX_LZ_CERTSTORE_HUB].size);
		} else {
			if (ta_update->info.certTable[INDEX_LZ_CERTSTORE_HUB].size >
				ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].size) {
				if (ta_copy.info.cursor + (ta_update->info.certTable[INDEX_LZ_CERTSTORE_HUB].size -
										   ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].size) >
					sizeof(ta_copy.certBag)) {
					dbgprint(DBG_ERR, "ERROR: DeviceID issuer root cert to be updated is larger "
									  "than old one and would exceed certBag size\n");
					return LZ_ERROR;
				}
			}

			memcpy(&ta_copy.certBag[ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].start],
				   &(ta_update->certBag[ta_update->info.certTable[INDEX_LZ_CERTSTORE_HUB].start]),
				   ta_update->info.certTable[INDEX_LZ_CERTSTORE_HUB].size);
			ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].size =
				ta_update->info.certTable[INDEX_LZ_CERTSTORE_HUB].size;
			ta_copy.info.cursor = ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].start +
								  ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].size;
			ta_copy.certBag[ta_copy.info.cursor++] = '\0';

			if (ta_copy.info.certTable[INDEX_LZ_CERTSTORE_HUB].start <
				ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].start) {
				ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].start = ta_copy.info.cursor;
				memcpy((void *)&ta_copy
						   .certBag[ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].start],
					   (void *)&(lz_data_store.trust_anchors
									 .certBag[lz_data_store.trust_anchors.info
												  .certTable[INDEX_LZ_CERTSTORE_DEVICEID]
												  .start]),
					   ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size);
				ta_copy.info.cursor += ta_copy.info.certTable[INDEX_LZ_CERTSTORE_DEVICEID].size;
				ta_copy.certBag[ta_copy.info.cursor++] = '\0';
			}
		}
	}

	if (!(lzport_flash_write((uint32_t)&lz_data_store.trust_anchors, (void *)&ta_copy,
							 sizeof(lz_data_store.trust_anchors)))) {
		dbgprint(DBG_ERR, "ERROR: Failed to flash certs update\n");
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

/**
 * Apply a staged config data update. The backend must zero all config data elements that should
 * not be updated so that partial updates of the config data are possbile
 * @param staging_elem_hdr The staging element header of the config data update to be applied
 * @return LZ_SUCCESS on success, otherwise LZ_ERROR
 */
static LZ_RESULT lz_apply_config_update(lz_auth_hdr_t *staging_elem_hdr)
{
	lz_config_data_t cfg_copy = { 0 };
	lz_config_data_t *cfg_update;

	// Check whether size matches
	if (sizeof(cfg_copy) != (staging_elem_hdr->content.payload_size)) {
		dbgprint(DBG_ERR,
				 "ERROR: Config update size (%d) does not match size of CONFIG_DATA "
				 "structure (%d).\n",
				 staging_elem_hdr->content.payload_size, sizeof(cfg_copy));
		return LZ_ERROR;
	}

	// Copy structure to be updated to RAM, rewrite, reflash
	memcpy((void *)&cfg_copy, (void *)&lz_data_store.config_data, sizeof(cfg_copy));

	cfg_update = (lz_config_data_t *)(((uint32_t)staging_elem_hdr) + sizeof(lz_auth_hdr_t));

	// Not allowed: STATIC_SYMM_INFO update, this is exclusively managed by the device
	// TODO could be refactored so that static_symm is not part of this structure and cannot be
	// updated in the first place
	if (!lz_is_mem_zero(&(cfg_update->static_symm_info), sizeof(cfg_update->static_symm_info))) {
		dbgprint(DBG_ERR, "ERROR: STATIC_SYMM_INFO struct cannot be remotely updated.\n");
		return LZ_ERROR;
	}

	// Not allowed: IMG_INFO update, this is exclusively managed by the device
	if (!lz_is_mem_zero(&(cfg_update->img_info), sizeof(cfg_update->img_info))) {
		dbgprint(DBG_ERR, "ERROR: IMG_INFO struct cannot be remotely updated.\n");
		return LZ_ERROR;
	}

	// We currently only have one updatable element, so this must necessarily be the thing to update
	memcpy(&cfg_copy.nw_info, &(cfg_update->nw_info), sizeof(cfg_update->nw_info));

	if (!(lzport_flash_write((uint32_t)&lz_data_store.config_data, (void *)&cfg_copy,
							 sizeof(lz_data_store.config_data)))) {
		dbgprint(DBG_ERR, "ERROR: Failed to flash config update\n");
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

static LZ_RESULT lz_apply_img_update(lz_auth_hdr_t *staging_elem_hdr)
{
	uint8_t *flash_image_start;
	uint8_t *staged_image_start;

	// Check whether the update fits into the image bounds
	if (!lz_check_update_size(staging_elem_hdr)) {
		dbgprint(DBG_ERR, "ERROR: Update image size exceeds bounds.\n");
		return LZ_ERROR;
	}

	// Get image address depending on the image type
	switch (staging_elem_hdr->content.type) {
	case LZ_UDOWNLOADER_UPDATE:
		flash_image_start = (uint8_t *)&lz_udownloader_hdr;
		break;
	case LZ_CPATCHER_UPDATE:
		flash_image_start = (uint8_t *)&lz_cpatcher_hdr;
		break;
	case APP_UPDATE:
		flash_image_start = (uint8_t *)&lz_app_hdr;
		break;
	default:
		dbgprint(DBG_ERR, "ERROR: Cannot locate unknown update image type %s\n",
				 HDR_TYPE_STRING[staging_elem_hdr->content.type]);
		return LZ_ERROR;
	}

	// Determine the start address of the update
	staged_image_start = (uint8_t *)(((uint32_t)staging_elem_hdr) + sizeof(lz_auth_hdr_t));

	// Finally, flash the staged update, assuming that it is contiguous and in its full length on staging area
	dbgprint(DBG_INFO,
			 "INFO: Flashing staged update from staging area (0x%x) to update area "
			 "(0x%x)\n",
			 (uint32_t)staged_image_start, (uint32_t)flash_image_start);

	if (!(lzport_flash_write((uint32_t)flash_image_start, (uint8_t *)staged_image_start,
							 staging_elem_hdr->content.payload_size))) {
		dbgprint(DBG_ERR, "ERROR: Flashing the update failed.\n");
		return LZ_ERROR;
	}

	dbgprint(DBG_INFO, "INFO: Flashing update successful\n");

	return LZ_SUCCESS;
}

/**
 * Verifies an update. Must be performed before the update is actually applied
 * @param staging_elem_hdr
 * @return LZ_SUCCESS on success, otherwise LZ_ERROR
 */
static LZ_RESULT lz_verify_img_hdr(lz_auth_hdr_t *staging_hdr)
{
	// Layout: staging_elem_hdr | img_hdr | img_code
	lz_img_hdr_t *img_hdr = (lz_img_hdr_t *)(((uint32_t)staging_hdr) + sizeof(lz_auth_hdr_t));
	uint8_t *img_code = (uint8_t *)(((uint32_t)img_hdr) + sizeof(lz_img_hdr_t));
	const lz_img_meta_t *img_meta;

	if (lz_get_img_meta(staging_hdr, &img_meta) != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Could not get header and code information of update image.\n");
		return LZ_ERROR;
	}

	return lz_core_verify_image(img_hdr, img_code, img_meta, NULL);
}

/**
 * Gets the address of the staged image's current meta data from Lazarus Data
 * @param staging_elem_hdr Used to determine the update type and corresponding meta data
 * @param img_meta Pointer to retrieve the image's meta data
 * @return LZ_SUCCESS on success, otherwise LZ_ERROR
 */
static LZ_RESULT lz_get_img_meta(lz_auth_hdr_t *staging_elem_hdr, const lz_img_meta_t **img_meta)
{
	// Meta data of image type to be verified is in Lazarus Data Store
	switch (staging_elem_hdr->content.type) {
	case LZ_CORE_UPDATE:
		if (img_meta != NULL)
			*img_meta = (lz_img_meta_t *)&lz_data_store.config_data.img_info.rc_meta;
		break;
	case LZ_UDOWNLOADER_UPDATE:
		if (img_meta != NULL)
			*img_meta = (lz_img_meta_t *)&lz_data_store.config_data.img_info.ud_meta;
		break;
	case LZ_CPATCHER_UPDATE:
		if (img_meta != NULL)
			*img_meta = (lz_img_meta_t *)&lz_data_store.config_data.img_info.um_meta;
		break;
	case APP_UPDATE:
		if (img_meta != NULL)
			*img_meta = (lz_img_meta_t *)&lz_data_store.config_data.img_info.app_meta;
		break;
	default:
		dbgprint(DBG_ERR, "ERROR: Cannot locate unknown image type %s meta data\n",
				 HDR_TYPE_STRING[staging_elem_hdr->content.type]);
		return LZ_ERROR;
	}
	return LZ_SUCCESS;
}
