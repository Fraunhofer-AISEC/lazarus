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

#ifndef FLASH_API_H_
#define FLASH_API_H_

#include "fsl_iap.h"

/** The flash page size is 512 Bytes */
#define FLASH_PAGE_SIZE 0x200U
/** Secure flash start address */
#define FLASH_BASE_ADDR 0x00000000
/** Flash size is 640kB = 0xA0000, the last 20 pages are reserved */
#define FLASH_SIZE 0x9D800

bool lzport_flash_init(void);
bool lzport_flash_erase_page(uint32_t start);
bool lzport_flash_erase(uint32_t start, uint32_t size);
bool lzport_flash_write(uint32_t start, uint8_t *buf, uint32_t size);
bool lzport_flash_read(uint32_t addr, uint8_t *buffer, uint32_t size);
/**
 * Returns the 128-bit RFC4122 compliant Universally Unique Identifier (UUID)
 * of the device
 */
int lzport_retrieve_uuid(uint8_t uuid[LEN_UUID_V4_BIN]);

#endif /* FLASH_API_H_ */
