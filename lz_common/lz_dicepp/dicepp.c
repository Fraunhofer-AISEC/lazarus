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

#include "fsl_common.h"

#include "lz_config.h"
#include "lz_error.h"
#include "lz_common.h"
#include "lzport_debug_output.h"
#include "lzport_dice.h"
#include "lzport_rng.h"
#include "lzport_flash.h"
#include "lz_hmac.h"
#include "lz_sha256.h"
#include "dicepp.h"

// Flash and RAM data structures according to the linker script. See notes on structure definitions in .h file
__attribute__((section(".DICEPP_DATA"))) volatile const dicepp_data_store_t dicepp_data_store;
__attribute__((section(".LZ_CORE_CODE"))) volatile const uint8_t lz_core_core[LZ_CORE_CODE_SIZE];
__attribute__((section(".RAM_DATA"))) volatile lz_core_boot_params_t lz_core_boot_params;

void dicepp_run(void)
{
	bool first_boot = true;
	boot_mode_t req_boot_mode; // boot mode requested by an upper layer before reboot
	dicepp_secret_data_t dicepp_secret_data;

	// Check whether DICEpp boots for the first time
	first_boot = dicepp_is_initial_boot();

	if (first_boot) {
		dbgprint(DBG_WARN, "WARNING: LZ_MAGIC not set. This is normal if this is the first boot\n");
		// Provision the DICEpp data store if this is the first launch
		if (dicepp_create_initial_boot_data() != LZ_SUCCESS) {
			dbgprint(DBG_ERR, "ERROR: Creating initial DICEpp data failed.\n");
			lz_error_handler();
		}
	} else {
		// Otherwise, just refresh the nonce in the DICEpp data store
		if (dicepp_refresh_nonces() != LZ_SUCCESS) {
			dbgprint(DBG_ERR, "ERROR: Could not renew nonces.\n");
			lz_error_handler();
		}
	}

	if (dicepp_create_secret_data(&dicepp_secret_data) != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Failed to create secret data (cdi, static_symm, ...)\n");
		lz_error_handler();
	}

	dicepp_determine_boot_mode(first_boot, &req_boot_mode);

	uint8_t cdi_prime[SHA256_DIGEST_LENGTH];
	uint8_t lz_core_digest[SHA256_DIGEST_LENGTH];
	if (dicepp_calculate_cdi_prime(cdi_prime, lz_core_digest, &dicepp_secret_data) != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Failed to create CDIprime\n");
		lz_error_handler();
	}

	uint8_t core_auth[SHA256_DIGEST_LENGTH];
	if (dicepp_calculate_core_auth(core_auth, lz_core_digest, &dicepp_secret_data) != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Failed to calculate core_auth\n");
		lz_error_handler();
	}

	// Write startup parameters for Lazarus Core to RAM
	dicepp_provide_params_ram(first_boot, &req_boot_mode, &dicepp_secret_data, cdi_prime,
							  core_auth);
}

/**
 * Check if this is the first boot of Dice++
 * @return true if it is the first boot, otherwise false
 */
bool dicepp_is_initial_boot(void)
{
	return dicepp_data_store.info.magic != LZ_MAGIC;
}

LZ_RESULT dicepp_create_secret_data(dicepp_secret_data_t *dicepp_secret_data)
{
	dbgprint(DBG_INFO, "INFO: Deriving static_symm from CDI and dev_uuid..\n");

	// Read CDI
	lzport_read_cdi(dicepp_secret_data->cdi, sizeof(dicepp_secret_data->cdi));

	// Create static_symm
	if (lz_hmac_sha256(dicepp_secret_data->static_symm,
					   (const void *)dicepp_data_store.info.dev_uuid, LEN_UUID_V4_BIN,
					   dicepp_secret_data->cdi, SHA256_DIGEST_LENGTH) != 0) {
		dbgprint(DBG_ERR, "ERROR: Creating static_symm failed.\n");
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

// Creates initial DICEpp data: CDI, first nonce, dev_uuid, static_symm
// Returns true if initial data creation and storing succeeds.
LZ_RESULT dicepp_create_initial_boot_data(void)
{
	dicepp_data_store_t dicepp_data_store_tmp = { 0 };

	dbgprint(DBG_INFO, "INFO: First boot - Generating initial data (magic val, UUID, nonces)\n");

	// identifier to recognize first boot
	dicepp_data_store_tmp.info.magic = LZ_MAGIC;

	// current_nonce remains uninitialized
	lzport_rng_get_random_data(dicepp_data_store_tmp.info.next_nonce,
							   sizeof(dicepp_data_store.info.next_nonce));

	// Create dev_uuid
	if (lzport_retrieve_uuid(dicepp_data_store_tmp.info.dev_uuid) != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Failed to create UUID\n");
		return LZ_ERROR;
	}

	// Write to flash page
	if (!(lzport_flash_write((uint32_t)&dicepp_data_store, (uint8_t *)&dicepp_data_store_tmp,
							 sizeof(dicepp_data_store)))) {
		dbgprint(DBG_ERR, "ERROR: Failed to flash initial boot data\n");
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

LZ_RESULT dicepp_calculate_cdi_prime(uint8_t cdi_prime[SHA256_DIGEST_LENGTH],
									 uint8_t lz_core_digest[SHA256_DIGEST_LENGTH],
									 dicepp_secret_data_t *dicepp_secret_data)
{
	// Hash Lazarus Core to calculate CDI_prime
	if (lz_sha256(lz_core_digest, (const void *)lz_core_core,
				  (LZ_CORE_CODE_SIZE + LZ_CORE_NSC_SIZE)) != 0) {
		dbgprint(DBG_ERR, "ERROR: Failed to hash Lazarus Core code area\n");
		return LZ_ERROR;
	}

	// Calculate CDI_prime based on CDI and Lazarus Core's hash, and store it
	if (lz_hmac_sha256(cdi_prime, lz_core_digest, SHA256_DIGEST_LENGTH,
					   (uint8_t *)dicepp_secret_data->cdi, SHA256_DIGEST_LENGTH) != 0) {
		dbgprint(DBG_ERR, "ERROR: Failed to create CDIprime\n");
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

LZ_RESULT dicepp_calculate_core_auth(uint8_t core_auth[SHA256_DIGEST_LENGTH],
									 uint8_t lz_core_digest[SHA256_DIGEST_LENGTH],
									 dicepp_secret_data_t *dicepp_secret_data)
{
	uint8_t digest_core_auth[SHA256_DIGEST_LENGTH + LEN_UUID_V4_BIN];

	// Concatenate Lazarus Core hash with UUID, which serves as digest for core_auth calculation
	memcpy(digest_core_auth, lz_core_digest, SHA256_DIGEST_LENGTH);
	memcpy(digest_core_auth + SHA256_DIGEST_LENGTH, (void *)dicepp_data_store.info.dev_uuid,
		   LEN_UUID_V4_BIN);

	// Calculate core_auth based on Lazarus Core's hash || dev_uuid and static_symm, and store it
	if (lz_hmac_sha256(core_auth, digest_core_auth, sizeof(digest_core_auth),
					   (uint8_t *)dicepp_secret_data->static_symm, SYM_KEY_LENGTH) != 0) {
		dbgprint(DBG_ERR, "ERROR: Failed to derive core auth\n");
		return LZ_ERROR;
	}
	return LZ_SUCCESS;
}

void dicepp_provide_params_ram(bool first_boot, boot_mode_t *boot_mode_req,
							   dicepp_secret_data_t *dicepp_secret_data,
							   uint8_t cdi_prime[SHA256_DIGEST_LENGTH],
							   uint8_t core_auth[SHA256_DIGEST_LENGTH])
{
	// Zero RAM handover region
	memset((void *)&lz_core_boot_params, 0x00, sizeof(lz_core_boot_params));

	// Copy dev_uuid
	memcpy((void *)lz_core_boot_params.info.dev_uuid, (void *)dicepp_data_store.info.dev_uuid,
		   LEN_UUID_V4_BIN);

	// Always copy nonces
	memcpy((void *)&lz_core_boot_params.info.cur_nonce, (void *)&dicepp_data_store.info.cur_nonce,
		   sizeof(lz_core_boot_params.info.cur_nonce));
	memcpy((void *)&lz_core_boot_params.info.next_nonce, (void *)&dicepp_data_store.info.next_nonce,
		   sizeof(lz_core_boot_params.info.next_nonce));

	// Copy unauthenticated bare requested boot mode
	memset((void *)&lz_core_boot_params.info.req_boot_mode, *boot_mode_req,
		   sizeof(lz_core_boot_params.info.req_boot_mode));

	if (first_boot) {
		// Symmetric secret must only be revealed on first boot
		memcpy((void *)&lz_core_boot_params.info.static_symm, dicepp_secret_data->static_symm,
			   SYM_KEY_LENGTH);
		// Indicate that it is the first boot. Just write 0x1 to first byte
		memset((void *)&lz_core_boot_params.info.initial_boot, 0x1, sizeof(uint8_t));
	}

	// Copy CDIprime
	memcpy((void *)&lz_core_boot_params.info.cdi_prime, cdi_prime, SHA256_DIGEST_LENGTH);

	// Copy core auth
	memcpy((void *)&lz_core_boot_params.info.core_auth, core_auth, SHA256_DIGEST_LENGTH);

	// Set magic value to indicate boot parameters are sane
	lz_core_boot_params.info.magic = LZ_MAGIC;
}

// Write the determined boot mode to <boot_mode>.
// In case of the first boot, we always boot into the UD.
// Returns true on success.

/**
 * Determine the boot mode. Upper layers can request a boot mode (unauthenticated). Lazarus
 * will follow the request only if a boot ticket is available and it is not the first boot. In
 * this case, we usually boot into the APP, however, the APP might decide that it wants to boot
 * e.g. into the update downloader
 * @param first_boot Indicator whether this is the first ever boot of Dice++
 * @param boot_mode The boot-mode to be determined
 */
void dicepp_determine_boot_mode(bool first_boot, boot_mode_t *boot_mode)
{
	if (first_boot) {
		// Boot into UD for initial backend-provisioning, e.g. to provide wrapped static_symm to backend
		*boot_mode = LZ_UDOWNLOADER;
	} else {
		// Get unauthenticated boot mode flag written to flash by upper layer.
		*boot_mode = (boot_mode_t)((uint32_t) * ((uint32_t *)BOOT_MODE_WORD_LOCATION));
	}
}

// Create a new next_nonce, and take old next_nonce to store it into cur_nonce
LZ_RESULT dicepp_refresh_nonces(void)
{
	dicepp_data_store_t dicepp_data_store_cpy;

	memcpy((void *)&dicepp_data_store_cpy, (void *)&dicepp_data_store,
		   sizeof(dicepp_data_store_cpy));

	// Next goes into current
	memcpy((void *)&dicepp_data_store_cpy.info.cur_nonce,
		   (void *)&dicepp_data_store.info.next_nonce,
		   sizeof(dicepp_data_store_cpy.info.cur_nonce));

	// Create new next nonce
	lzport_rng_get_random_data(dicepp_data_store_cpy.info.next_nonce,
							   sizeof(dicepp_data_store_cpy.info.next_nonce));

	dbgprint_data(dicepp_data_store_cpy.info.next_nonce, LEN_NONCE, "Next Nonce");

	if (!lzport_flash_write((uint32_t)&dicepp_data_store, (uint8_t *)&dicepp_data_store_cpy,
							sizeof(dicepp_data_store))) {
		dbgprint(DBG_ERR, "ERROR: Failed to write nonces to flash\n");
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}
