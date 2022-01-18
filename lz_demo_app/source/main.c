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
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

#include "lz_config.h"
#include "lz_common/lz_common.h"
#include "lzport_debug_output/lzport_debug_output.h"
#include "lzport_memory/lzport_memory.h"
#include "lzport_usart/lzport_usart.h"
#include "lzport_rng/lzport_rng.h"
#include "lzport_gpio/lzport_gpio.h"
#include "lz_trustzone_handler/lz_awdt_handler.h"
#include "lz_awdt.h"
#include "lz_net/lz_net.h"

#include "net.h"
#include "sensor.h"
#include "lz_led.h"

#if (1 == FREERTOS_BENCHMARK_ACTIVE)
#include "benchmark.h"
#endif
unsigned char memory_buf[12 * 1024];

void SystemInit(void)
{
	// Set vector table offset register
	SCB->VTOR = LZ_APP_CODE_START;
}

int main(void)
{
	mbedtls_memory_buffer_alloc_init(memory_buf, sizeof(memory_buf));

	// Init board hardware.
	BOARD_InitBootPins();
	// Clocks are already configured, but variable must be set
	SystemCoreClock = BOARD_BOOTCLOCKFROHF96M_CORE_CLOCK;

	lzport_init_debug();
	lzport_gpio_port_init();
	lzport_rng_init();
	lzport_gpio_rts_init();
	lzport_gpio_set_rts(false);
	lz_print_img_info("Demo App", &lz_app_hdr);

#if (1 == FREERTOS_BENCHMARK_ACTIVE)
	vTraceEnable(TRC_INIT);
#endif

	lzport_usart_init_esp();

	xTaskCreate(net_task, "NET ", configMINIMAL_STACK_SIZE * 10, NULL, 5, NULL);
	xTaskCreate(lz_awdt_task, "ADT ", configMINIMAL_STACK_SIZE * 5, NULL, 4, NULL);
#if (RUN_IOT_SENSOR_DEMO == 1)
	xTaskCreate(sensor_task, "DEM", configMINIMAL_STACK_SIZE * 6, NULL, 3, NULL);
#endif
	xTaskCreate(led_task, "LED ", configMINIMAL_STACK_SIZE, NULL, 3, NULL);
#if (1 == FREERTOS_BENCHMARK_ACTIVE)
	xTaskCreate(benchmark_task, "MRK", configMINIMAL_STACK_SIZE * 20, NULL, 5, NULL);
#endif

	vTaskStartScheduler();

	for (;;)
		;

	return 0;
}

void freertos_assert_called(const char *file, uint32_t line)
{
	dbgprint(DBG_ERR, "ERROR: FreeRTOS assert called: File %s, line %d\n", file, line);
	for (;;)
		;
}
