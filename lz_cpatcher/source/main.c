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
#include "board.h"
#include "peripherals.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "LPC55S69_cm33_core0.h"

#include "lz_common/lz_common.h"
#include "lz_config.h"
#include "lzport_debug_output/lzport_debug_output.h"
#include "lzport_memory/lzport_memory.h"
#include "lzport_flash/lzport_flash.h"
#include "lzport_rng/lzport_rng.h"
#include "lzport_gpio/lzport_gpio.h"
#include "exception_handler.h"
#include "lz_cpatcher.h"

// typedef for non-secure callback functions
typedef void (*funcptr_ns)(void) __attribute__((cmse_nonsecure_call));

void SystemInit(void)
{
}

int main(void)
{
	// Init board hardware.
	BOARD_InitBootPins();
	// Clock config was already done, but SystemCoreClock variable must be set
	SystemCoreClock = BOARD_BOOTCLOCKFROHF96M_CORE_CLOCK;

	lzport_init_debug();
	lzport_flash_init();
	lz_print_img_info("Lazarus Update Patcher", &lz_cpatcher_hdr);

	lz_core_patcher_run();

	return 0;
}
