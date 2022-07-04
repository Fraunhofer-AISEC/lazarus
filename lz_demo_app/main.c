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
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

#include "lz_config.h"
#include "lz_common.h"
#include "lzport_debug_output.h"
#include "lzport_memory.h"
#include "lzport_usart.h"
#include "lzport_rng.h"
#include "lzport_gpio.h"
#include "lz_awdt_handler.h"
#include "lz_awdt.h"
#include "lz_net.h"
#include "net.h"

int main(void)
{
	lzport_demo_app_init_board();

	lzport_init_debug();
	lzport_gpio_port_init();
	lzport_rng_init();
	lzport_gpio_rts_init();
	lzport_gpio_set_rts(false);
	lz_print_img_info("Demo App", &lz_app_hdr);
	lzport_usart_init_esp();

	xTaskCreate(net_task, "NET ", configMINIMAL_STACK_SIZE * 10, NULL, 5, NULL);
	xTaskCreate(lz_awdt_task, "ADT ", configMINIMAL_STACK_SIZE * 5, NULL, 4, NULL);

	vTaskStartScheduler();

	// Should never be reached
	return 0;
}

void freertos_assert_called(const char *file, uint32_t line)
{
	dbgprint(DBG_ERR, "ERROR: FreeRTOS assert called: File %s, line %d\n", file, line);
	for (;;)
		;
}
