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

#include <stdio.h>
#include "arm_cmse.h"
#include "board.h"
#include "peripherals.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "LPC55S69_cm33_core0.h"
#include "fsl_power.h"

#include "lz_ecc.h"
#include "lz_ecdsa.h"
#include "lz_sha256.h"

#include "lz_common.h"
#include "lz_config.h"
#include "lzport_memory.h"
#include "lzport_debug_output.h"
#include "lzport_throttle_timer.h"
#include "lz_core.h"
#include "lz_update.h"
#include "exception_handler.h"

typedef void (*funcptr_s_t)(void);
typedef void (*funcptr_ns_t)(void) __attribute__((cmse_nonsecure_call));

// Already performed in lz_dicepp
void SystemInit(void)
{
}

void lzport_core_board_init(void)
{
	/* Init board hardware. */
	BOARD_InitBootPins();
	// Clock config was already done, but SystemCoreClock variable must be set
	SystemCoreClock = BOARD_BOOTCLOCKFROHF96M_CORE_CLOCK;
}

void switch_to_next_layer(boot_mode_t boot_mode)
{
	if (LZ_CPATCHER == boot_mode) {
		dbgprint(DBG_INFO, "INFO: Entering SECURE Core Patcher from Lazarus Core at %x..\n",
				 LZ_CPATCHER_CODE_START);

		funcptr_s_t re_um = (funcptr_s_t)(*((uint32_t *)((LZ_CPATCHER_CODE_START) + 4U)));

		re_um();
	} else if (LZ_UDOWNLOADER == boot_mode) {
		dbgprint(DBG_INFO,
				 "INFO: Entering NON_SECURE Update Downloader from Lazarus Core at %x..\n",
				 LZ_UD_CODE_START);

		funcptr_ns_t ud_ns = (funcptr_ns_t)(*((uint32_t *)(LZ_UD_CODE_START + 4U)));

		ud_ns();
	} else if (APP == boot_mode) {
		dbgprint(DBG_INFO, "INFO: Entering NON_SECURE App from Lazarus Core at %x..\n",
				 LZ_APP_CODE_START);

		funcptr_ns_t app_ns = (funcptr_ns_t)(*((uint32_t *)(LZ_APP_CODE_START + 4U)));

		app_ns();
	}
}
