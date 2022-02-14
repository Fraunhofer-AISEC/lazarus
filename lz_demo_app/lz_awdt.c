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
#include "stdio.h"
#include "fsl_common.h"

#include "FreeRTOS.h"
#include "task.h"

#include "lz_config.h"
#include "lzport_memory.h"
#include "lzport_debug_output.h"
#include "lzport_gpio.h"
#include "lz_common.h"
#include "lz_net.h"
#include "lz_awdt.h"
#include "lz_led.h"

#include "sensor.h"
#include "benchmark.h"

static TaskHandle_t task_awdt_handle = NULL;

void lz_awdt_task(void *params)
{
	task_awdt_handle = xTaskGetCurrentTaskHandle();
	// TODO better solution
	uint32_t multiple = 0;

	// Wait until network connection is established
	ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(portMAX_DELAY));

	TickType_t last_wake_time = xTaskGetTickCount();

	// Periodically fetch new deferral tickets to avoid a system reset
	for (;;) {
		multiple++;

		// Trigger flashing the blue LED to indicate that a deferral ticket is to be fetched
		xTaskNotifyGive(get_led_task_handle());

#if (RUN_IOT_SENSOR_DEMO == 1)
		if ((multiple % DEFERRAL_TICKET_FETCHING_MULT) == 0) {
#endif
			dbgprint(DBG_INFO, "INFO: Fetching deferral ticket with a time of %ds..\n",
					 DEFERRAL_TICKET_TIME_MS / 1000);

			LZ_RESULT result = lz_net_refresh_awdt(DEFERRAL_TICKET_TIME_MS);

			if (result == LZ_SUCCESS) {
				lzport_gpio_set_status_led(true, LED_ON);
			} else {
				lzport_gpio_set_status_led(false, LED_ON);
			}
#if (RUN_IOT_SENSOR_DEMO == 1)
		}
		// TODO own task
		send_sensor_data();
#endif

		dbgprint(DBG_INFO, "INFO: Waiting for %dms\n", DEFERRAL_TICKET_TASK_WAIT_MS);
		vTaskDelayUntil(&last_wake_time, pdMS_TO_TICKS(DEFERRAL_TICKET_TASK_WAIT_MS));

#if (1 == FREERTOS_BENCHMARK_ACTIVE)
		// Trigger run-time evaluation
		xTaskNotifyGive(get_benchmark_task_handle());
#endif
	}
}

TaskHandle_t get_task_awdt_handle(void)
{
	return task_awdt_handle;
}
