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

#ifndef lzport_LPC55S69_lzport_MEMORY_H_
#define lzport_LPC55S69_lzport_MEMORY_H_

// Attention
// If something is changed here, it also has to be changed in the linker script

#define LZ_IMG_HDR_SIZE 0x00000800

#define LZ_DICEPP_CODE_START 0x10000000
#define LZ_DICEPP_CODE_SIZE 0x00008000
#define LZ_DICEPP_DATA_START 0x10008000
#define LZ_DICEPP_DATA_SIZE 0x00000800
#define LZ_CORE_IRQ_START 0x1000F800
#define LZ_CORE_IRQ_SIZE 0x00000800

#define LZ_CORE_HEADER_START 0x10010000
#define LZ_CORE_HEADER_SIZE LZ_IMG_HDR_SIZE
#define LZ_CORE_CODE_START 0x10010800
#define LZ_CORE_CODE_SIZE 0x00017400
#define LZ_CORE_NSC_START 0x10027C00
#define LZ_CORE_NSC_SIZE 0x00000400

#define LZ_CPATCHER_HEADER_START 0x10028000
#define LZ_CPATCHER_HEADER_SIZE LZ_IMG_HDR_SIZE
#define LZ_CPATCHER_CODE_START 0x10028800
#define LZ_CPATCHER_CODE_SIZE 0x0000F800

#define LZ_UD_HEADER_START 0x00038000
#define LZ_UD_HEADER_SIZE LZ_IMG_HDR_SIZE
#define LZ_UD_CODE_START 0x00038800
#define LZ_UD_CODE_SIZE 0x0000F800

#define LZ_APP_HEADER_START 0x00048000
#define LZ_APP_HEADER_SIZE LZ_IMG_HDR_SIZE
#define LZ_APP_CODE_START 0x00048800
#define LZ_APP_CODE_SIZE 0x00027800

#define LZ_DATA_STORAGE_START 0x00070000
#define LZ_DATA_STORAGE_SIZE 0x00002000

#define LZ_STAGING_AREA_START 0x00072000
#define LZ_STAGING_AREA_SIZE 0x00028000

#define LZ_STAGING_AREA_END (LZ_STAGING_AREA_START + LZ_STAGING_AREA_SIZE - 4)
#define LZ_STAGING_AREA_NUM_PAGES 320

#define LZ_FLASH_NS_START LZ_UD_HEADER_START
#define LZ_FLASH_NS_SIZE                                                                           \
	(LZ_UD_HEADER_SIZE + LZ_UD_CODE_SIZE + LZ_APP_HEADER_SIZE + LZ_APP_CODE_SIZE +                 \
	 LZ_DATA_STORAGE_SIZE + LZ_STAGING_AREA_SIZE)

#define RAM_S_START 0x30000000
#define RAM_S_SIZE 0x00008000

#define RAM_NS_START 0x20008000
#define RAM_NS_SIZE 0x00038000

#define LZ_SRAM_PARAMS_START 0x20008000
#define LZ_SRAM_PARAMS_SIZE 0x00001800

#define LZ_SRAM_STACK_TOP_NS 0x20040000

/* All peripherals except ctimer2 which is used for the watchdog are configured unsecure so that
 * they can be used in the sample app */
#define PERIPH_NS_START_1 0x40000000
#define PERIPH_NS_SIZE_1 0x00028000

#define PERIPH_NS_START_2 CTIMER3_BASE_NS
#define PERIPH_NS_SIZE_2 0x0FFD7000

void lzport_asm_zero_ram(uint32_t start, uint32_t size);

#endif /* lzport_LPC55S69_lzport_MEMORY_H_ */
