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

#ifndef LZ_CORE_H_
#define LZ_CORE_H_

#include "ecc.h"
#include "ecdsa.h"

boot_mode_t lz_core_run(void);

LZ_RESULT lz_core_create_device_id_csr(bool first_boot, lz_ecc_keypair *lz_keypair);

LZ_RESULT lz_core_provide_params_ram(boot_mode_t boot_mode, bool lz_core_updated,
									 bool firmware_update_necessary,
									 lz_ecc_keypair *lz_alias_id_keypair,
									 lz_ecc_keypair *lz_dev_id_keypair);

LZ_RESULT lz_core_derive_device_id(lz_ecc_keypair *lz_keypair);

bool lz_core_is_updated(lz_ecc_keypair *lz_pub);

LZ_RESULT lz_get_deferral_time(uint32_t *deferral_time);

LZ_RESULT lz_has_staging_elem_type(hdr_type_t elem_type);

LZ_RESULT lz_verify_staging_header(const lz_auth_hdr_t *staging_element_hdr, uint8_t *payload);

LZ_RESULT lz_has_valid_staging_element(hdr_type_t hdr_type);

void lz_get_curr_nonce(uint8_t *nonce);

LZ_RESULT lz_core_verify_next_layer(boot_mode_t boot_mode, uint8_t *next_layer_digest);

LZ_RESULT lz_core_store_static_symm(void);

uint32_t lz_get_num_staging_elems(void);

LZ_RESULT lz_core_erase_staging_area(void);

LZ_RESULT lz_core_erase_lz_data_store(void);

bool lz_core_is_initial_boot(void);

bool lz_core_is_provisioning_complete(void);

bool lz_core_boot_params_valid(void);

LZ_RESULT lz_core_wipe_static_symm(void);

/**
 * Verify an image regarding version number, issue time and signature
 * @param image_hdr The header to be verified
 * @param image_code The image
 * @param image_meta The image meta data
 * @param image_digest_out Hash of the code binary, must be of SHA256_DIGEST_LENGTH
 * @return LZ_SUCCESS, if the image could be verified, LZ_ERROR otherwise
 */
LZ_RESULT lz_core_verify_image(const lz_img_hdr_t *image_hdr, const uint8_t *image_code,
							   const lz_img_meta_t *image_meta, uint8_t *image_digest_out);

LZ_RESULT lz_core_verify_staging_elem_hdr_sig(const lz_auth_hdr_t *hdr, uint8_t *payload);

LZ_RESULT lz_core_verify_staging_elem_hdr(const lz_auth_hdr_t *hdr, uint8_t *payload,
										  uint8_t *nonce);

LZ_RESULT lz_core_derive_alias_id_keypair(uint8_t *digest, lz_ecc_keypair *lz_alias_id_keypair);

#endif /* LZ_CORE_H_ */
