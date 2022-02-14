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

#include "stdint.h"
#include "stdbool.h"
#include "stddef.h"
#include "lzport_debug_output.h"
#include "lzport_memory.h"
#include "lzport_dice.h"
#include "lz_common.h"

void lzport_read_cdi(uint8_t *data, uint32_t len)
{
	if (len != SHA256_DIGEST_LENGTH) {
		dbgprint(DBG_ERR, "ERROR: specified CDI length (%d) is invalid (must be %d)", len,
				 SHA256_DIGEST_LENGTH);
		lz_error_handler();
	}

#warning Check DICE CDI Derivation (DICEpp must be a secure boot image)
	//	LPC55S6x User manual Revision 1.0 page 1009
	//  "LPC55S6x (secure part) supports Device Identifier Composition Engine (DICE) to provide
	//	Composite Device Identifier (CDI). CDI value would be available at SYSCON offset
	//	0x0900 to 0x091C for consumption after boot completion. It is recommended to overwrite
	//	these registers once ephemeral key-pairs are generated using this value."
	//  This only works if DICEpp is an NXP secure boot image
	//  FIXME SYSCON->DICE_REG0 is not part of SDK 2.11
	memcpy(data, (void *)&SYSCON->RESERVED_34[240], SHA256_DIGEST_LENGTH);
}
