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
#include "lz_common.h"
#include "lzport_debug_output.h"
#include "lzport_memory.h"
#include "lz_net.h"
#include "lz_udownloader.h"

LZ_RESULT lz_udownloader_run(void)
{
	LZ_RESULT result = LZ_ERROR;

	// Check whether we have valid boot parameters provided by Lazarus Core
	if (lz_has_valid_boot_params() != LZ_SUCCESS) {
		ERROR("Corrupted boot parameters.\n");
		return LZ_ERROR;
	}

	// Print the parameters
	lz_print_cert_store();

	// Setup ESP8266, connect to Wi-Fi AP
	if (lz_net_init() != LZ_SUCCESS) {
		ERROR("Could not initialize network connection.\n");
		return LZ_ERROR;
	}

	// Open socket
	if (LZ_SUCCESS != lz_net_open()) {
		ERROR("ERROR Failed to open socket\n");
		return LZ_ERROR;
	}

	// DeviceID reassotiation is necessary after Lazarus Core updates. The Lazarus Core update
	// protocol involving dev_auth and UUID is performed
	INFO("Checking if device re-association is necessary..\n");
	if (lz_dev_reassociation_necessary()) {
		INFO("Re-associating device..\n");
		if (lz_reassociate_device() != LZ_SUCCESS) {
			// This means, that the Server does not agree with the Lazarus Core version that is
			// running. In this case, we can only try to update Lazarus Core again.
			ERROR("Failed to re-associate device\n");
			goto out;
		} else {
			INFO("Received new DeviceID. Rebooting to verify and apply\n");
			result = LZ_SUCCESS;
			goto out;
		}
	} else {
		INFO("Device re-association not required\n");
	}

	INFO("Sending AliasID certificate\n");
	if (lz_net_send_alias_id_cert() != LZ_SUCCESS) {
		WARN("Updating AliasID cert in backend not successful\n");
		goto out;
	}

	// Check if a firmware update is necessary. This is signaled by Lazarus Core if the firmware
	// could not be verified
	INFO("Checking if firmware update is necessary..\n");
	if (lz_firmware_update_necessary()) {
		INFO("Performing firmware update..\n");
		if (lz_net_fw_update(APP_UPDATE) == LZ_SUCCESS) {
			if (lz_set_boot_mode_request(APP_UPDATE) != LZ_SUCCESS) {
				WARN("Failed to set boot mode request\n");
			}
		} else {
			WARN("Failed to download update from hub\n");
			goto out;
		}
	} else {
		INFO("Firmware update not required\n");
	}

	// Get a new boot ticket, as the Update Downloader will trigger a reset when it is finished.
	// On the next boot, Lazarus Core can then switch to the firmware directly
	if (lz_net_refresh_boot_ticket() != LZ_SUCCESS) {
		WARN("Could not retrieve a boot ticket from backend.\n");
		goto out;
	} else {
		if (lz_set_boot_mode_request(APP) != LZ_SUCCESS) {
			WARN("Failed to set boot mode request to APP\n");
		}
	}

	result = LZ_SUCCESS;

out:
	lz_net_close();
	return result;
}

void lz_print_cert_store(void)
{
	INFO("Printing certificate store\n");

	INFO("DeviceID pubkey:\n%s\n", &lz_img_cert_store.info.dev_pub_key.key);

	INFO("CodeAuthority pubkey:\n%s\n", &lz_img_cert_store.info.code_auth_pub_key.key);

	INFO("Hub Public Key:\n%s\n", &lz_img_cert_store.info.management_pub_key.key);

	INFO("Certificate bag certificates:\n");
	for (uint32_t n = 0; n < NUM_CERTS; n++) {
		if (lz_img_cert_store.info.certTable[n].size > 0) {
			// We have a 0 byte between the PEM certificates in the certBag
			INFO("%s",
				 (char *)&lz_img_cert_store.certBag[lz_img_cert_store.info.certTable[n].start]);
		}
		INFO("\n");
	}
}

LZ_RESULT lz_reassociate_device(void)
{
	lz_img_cert_store.certBag[lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_DEVICEID].start];

	INFO("Trying to reassociate device\n");

	if (lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_DEVICEID].size == 0) {
		ERROR("Failed to read DeviceID CSR from certbag: Size is 0\n");
	}

	// There is a 0 byte between the PEM certificates in the certBag
	INFO("DeviceID CSR:\n%s\n",
		 (char *)&lz_img_cert_store
			 .certBag[lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_DEVICEID].start]);

	return lz_net_reassociate_device(
		(uint8_t *)lz_img_boot_params.info.dev_uuid, (uint8_t *)lz_img_boot_params.info.dev_auth,
		(uint8_t *)&lz_img_cert_store
			.certBag[lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_DEVICEID].start],
		lz_img_cert_store.info.certTable[INDEX_IMG_CERTSTORE_DEVICEID].size);
}
