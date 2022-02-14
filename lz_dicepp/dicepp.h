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

#ifndef DICEPP_H_
#define DICEPP_H_

// Boot mode can be set by writing to the end of the staging area
#define BOOT_MODE_WORD_LOCATION LZ_STAGING_AREA_END

/**
 * 2k dicepp data storage area
 */
typedef struct {
	uint32_t magic; // Used to recognize first DICEpp boot
	uint8_t
		cur_nonce[LEN_NONCE]; // This one is used for verifying elements pushed onto the staging area
	uint8_t next_nonce
		[LEN_NONCE]; // This is the nonce which we feed the server with during the current run, used within the next reboot
	uint8_t dev_uuid[LEN_UUID_V4_BIN]; // Dev_uuid for Lazarus updates
} dicepp_data_store_info_t;

typedef union {
	dicepp_data_store_info_t info;
	uint8_t u8[0x800];
	uint32_t u32[0x200];
} dicepp_data_store_t;

typedef struct {
	uint8_t cdi[SHA256_DIGEST_LENGTH];
	uint8_t static_symm[SYM_KEY_LENGTH];
} dicepp_secret_data_t;

void dicepp_run(void);
bool dicepp_is_initial_boot(void);
LZ_RESULT dicepp_create_secret_data(dicepp_secret_data_t *dicepp_temp_data);
void dicepp_determine_boot_mode(bool first_boot, boot_mode_t *boot_mode);
LZ_RESULT dicepp_refresh_nonces(void);
LZ_RESULT dicepp_create_initial_boot_data(void);
LZ_RESULT dicepp_calculate_cdi_prime(uint8_t cdi_prime[SHA256_DIGEST_LENGTH],
									 uint8_t lz_core_digest[SHA256_DIGEST_LENGTH],
									 dicepp_secret_data_t *dicepp_secret_data);
LZ_RESULT dicepp_calculate_core_auth(uint8_t core_auth[SHA256_DIGEST_LENGTH],
									 uint8_t lz_core_digest[SHA256_DIGEST_LENGTH],
									 dicepp_secret_data_t *dicepp_secret_data);
void dicepp_provide_params_ram(bool first_boot, boot_mode_t *boot_mode_req,
							   dicepp_secret_data_t *dicepp_secret_data,
							   uint8_t cdi_prime[SHA256_DIGEST_LENGTH],
							   uint8_t core_auth[SHA256_DIGEST_LENGTH]);

#endif /* DICEPP_H_ */
