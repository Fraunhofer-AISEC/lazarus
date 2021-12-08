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

#include "lz_config.h"
#include "lz_common/lz_common.h"
#include "lzport_debug_output/lzport_debug_output.h"
#include "lzport_memory/lzport_memory.h"
#include "lz_net/lz_net.h"
#include "lz_udownloader.h"

void lz_udownloader_run(void)
{
	// Check whether we have valid boot parameters provided by Lazarus Core
	if (lz_has_valid_boot_params() != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Corrupted boot parameters.\n");
		lz_error_handler();
	}

	// Print the parameters
	lz_print_cert_store();

	// Setup ESP8266, connect to Wi-Fi AP
	if (lz_net_init() != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Could not initialize network connection.\n");
		lz_error_handler();
	}

	// DeviceID reassotiation is necessary after Lazarus Core updates. The Lazarus Core update
	// protocol involving dev_auth and UUID is performed
	if (lz_dev_reassociation_necessary()) {
		if (lz_reassociate_device() != LZ_SUCCESS) {
			// This means, that the Server does not agree with the Lazarus Core version that is
			// running. In this case, we can only try to update Lazarus Core again.
			dbgprint(DBG_ERR, "ERROR: Failed to re-associate device\n");
			for (;;)
				;
		} else {
			dbgprint(DBG_INFO, "Received new DeviceID. Rebooting to verify and apply\n");
			return;
		}
	}

	if (lz_net_send_alias_id_cert() != LZ_SUCCESS) {
		dbgprint(DBG_WARN, "WARN: Updating AliasID cert in backend not successful\n");
	}

	// Check if a firmware update is necessary. This is signaled by Lazarus Core if the firmware
	// could not be verified
	if (lz_firmware_update_necessary()) {
		if (lz_net_fw_update(APP_UPDATE) == LZ_SUCCESS) {
			if (lz_set_boot_mode_request(APP_UPDATE) != LZ_SUCCESS) {
				dbgprint(DBG_WARN, "WARN: Failed to set boot mode request\n");
			}
		} else {
			dbgprint(DBG_WARN, "WARN: Failed to download update from hub\n");
		}
	}

	// Get a new boot ticket, as the Update Downloader will trigger a reset when it is finished.
	// On the next boot, Lazarus Core can then switch to the firmware directly
	if (lz_net_refresh_boot_ticket() != LZ_SUCCESS) {
		dbgprint(DBG_WARN, "WARN: Could not retrieve a boot ticket from backend.\n");
	} else {
		if (lz_set_boot_mode_request(APP) != LZ_SUCCESS) {
			dbgprint(DBG_WARN, "WARN: Failed to set boot mode request to APP\n");
		}
	}
}

void lz_print_cert_store(void)
{
	dbgprint(DBG_INFO, "INFO: Printing certificate store\n");

	dbgprint(DBG_INFO, "INFO: DeviceID pubkey:\n%s\n", &lz_img_cert_store.info.dev_pub_key.key);

	dbgprint(DBG_INFO, "INFO: CodeAuthority pubkey:\n%s\n",
			 &lz_img_cert_store.info.code_auth_pub_key.key);

	dbgprint(DBG_INFO, "INFO: Hub Public Key:\n%s\n",
			 &lz_img_cert_store.info.management_pub_key.key);

	dbgprint(DBG_INFO, "INFO: Certificate bag certificates:\n");
	for (uint32_t n = 0; n < NUM_CERTS; n++) {
		if (lz_img_cert_store.info.certTable[n].size > 0) {
			// We have a 0 byte between the PEM certificates in the certBag
			dbgprint(DBG_INFO, "%s",
					 (char *)&lz_img_cert_store.certBag[lz_img_cert_store.info.certTable[n].start]);
		}
		dbgprint(DBG_INFO, "\n");
	}
}

LZ_RESULT lz_reassociate_device(void)
{
	lz_img_cert_store.certBag[lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_DEVICEID].start];

	dbgprint(DBG_INFO, "INFO: Trying to reassociate device\n");

	if (lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_DEVICEID].size == 0) {
		dbgprint(DBG_ERR, "ERROR: Failed to read DeviceID CSR from certbag: Size is 0\n");
	}

	// There is a 0 byte between the PEM certificates in the certBag
	dbgprint(DBG_INFO, "DeviceID CSR:\n%s\n",
			 (char *)&lz_img_cert_store
				 .certBag[lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_DEVICEID].start]);

	return lz_net_reassociate_device(
		(uint8_t *)lz_img_boot_params.info.dev_uuid, (uint8_t *)lz_img_boot_params.info.dev_auth,
		(uint8_t *)&lz_img_cert_store
			.certBag[lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_DEVICEID].start],
		lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_DEVICEID].size);
}
