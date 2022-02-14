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

#include "board.h"
#include "peripherals.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "LPC55S69_cm33_core0.h"
#include "fsl_power.h"

#include "lz_config.h"
#include "lz_common.h"
#include "lzport_memory.h"
#include "lzport_flash.h"
#include "lzport_debug_output.h"
#include "dicepp.h"
#include "trustzone_config.h"

typedef void (*funcptr_s_t)(void);

static void dicepp_switch_to_lz_core(void);

int main(void)
{
	// Init board hardware
	POWER_SetBodVbatLevel(kPOWER_BodVbatLevel1650mv, kPOWER_BodHystLevel50mv, false);
	BOARD_InitBootPins();
	BOARD_BootClockFROHF96M();

	lzport_init_debug();
	lz_print_img_info("Lazarus DICE++", NULL);
	lzport_flash_init();

	dicepp_run();

	// The uC starts in secure mode with all memory being secure. Before we switch to lz_core, we
	// have to configure the TrustZone and Secure AHB Controller in order to allow non-secure
	// software to run in non-secure areas
#if (1 != DEV_DISABLE_TZ)
	dbgprint(DBG_INFO, "INFO: Configuring and enabling TrustZone\n");
	init_trustzone();
#endif
#if (1 != DEV_DISABLE_SAHBC)
	dbgprint(DBG_INFO, "INFO: Configuring and enabling Secure AHB Controller\n");
	init_secure_ahb_controller();
	print_secure_ahb_controller_status();
#endif

	dicepp_switch_to_lz_core();

	/* Enter an infinite loop, should never be reached */
	while (1) {
		__asm volatile("nop");
	}
	return 0;
}

void dicepp_switch_to_lz_core(void)
{
	funcptr_s_t lz_core = (funcptr_s_t)(*((uint32_t *)((LZ_CORE_CODE_START) + 4U)));

	// Set vector table of next binary
	SCB->VTOR = LZ_CORE_CODE_START;

	/* Already set the main stack pointer for the non-secure binaries because this is
	 * possible only in privileged level. Stack has the same address before both non-secure
	 * binaries */
	__TZ_set_MSP_NS((uint32_t)LZ_SRAM_STACK_TOP_NS);

	dbgprint(DBG_INFO, "INFO: Switching to unprivileged mode for Lazarus Core\n");

	// Force memory writes before continuing
	__DSB();
	// Flush and refill pipeline with updated permissions
	__ISB();

	// Switch to secure non-privileged mode (tier 2) for Lazarus Core
	__set_CONTROL(__get_CONTROL() | (0x1 << CONTROL_nPRIV_Pos));

	/* Jump to next binary */
	lz_core();
}
