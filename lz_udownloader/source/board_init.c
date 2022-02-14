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
#include "mbedtls/memory_buffer_alloc.h"

#include "lz_config.h"
#include "lz_common.h"
#include "lzport_debug_output.h"
#include "lzport_usart.h"
#include "lzport_rng.h"
#include "lzport_gpio.h"
#include "lzport_systick_delay.h"
#include "lz_net.h"
#include "lz_power_handler.h"
#include "lz_udownloader.h"

void SystemInit(void)
{
	// Set vector table offset register
	SCB->VTOR = LZ_UD_CODE_START;
}

int main(void)
{
	// Init board hardware.
	BOARD_InitBootPins();
	BOARD_InitBootPeripherals();
	// Clocks are already configured, but variable must be set
	SystemCoreClock = BOARD_BOOTCLOCKFROHF96M_CORE_CLOCK;

	// Toggle trace to indicate component has started
#if (1 == RE_DBG_TRACE_BOOT_ACTIVE)
	lzport_gpio_toggle_trace();
#endif

	lzport_init_debug();
	lz_print_img_info("Lazarus Update Downloader", &lz_udownloader_hdr);

	lzport_init_systick_1khz();
	lzport_usart_init_esp();
	lzport_gpio_rts_init();
	lzport_gpio_set_rts(false);
	lzport_rng_init();

	lz_udownloader_run();

	// Deinitialize peripherals
	lzport_deinit_systick();

	dbgprint(DBG_INFO, "INFO: UD functionality terminated. Rebooting..\n");

	NVIC_SystemReset();

	return 0;
}
