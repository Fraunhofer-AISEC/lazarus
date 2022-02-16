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
#include "FreeRTOS.h"
#include "task.h"
#include "lz_config.h"
#include "lzport_gpio.h"
#include "lzport_debug_output.h"
#include "lz_awdt.h"
#include "lz_led.h"

// TODO own task was only to have some tasks in the beginning, can be set in AWDT task now

static TaskHandle_t led_task_handle = NULL;

/**
 * This task visualizes the state of the lazarus device via the LPC55S69 board LED: continuous green
 * means that the device is working properly and fetching deferral tickets. The LED flashes blue
 * for 500ms whenever a new deferral ticket is fetched. If the fetching is not successful, the
 * LED is continuously red until it was again possible to fetch a ticket (or the device will reset).
 * The LED is off during boot.
 *
 * @param params FreeRTOS task parameters, can be NULL
 */
void led_task(void *params)
{
	led_task_handle = xTaskGetCurrentTaskHandle();

	for (;;) {
		uint32_t notification_value =
			ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(DEFERRAL_TICKET_TASK_WAIT_MS * 2));

		if (notification_value == 1) {
			// Indicate that a deferral ticket is to be fetched by the deferral ticket task
			lzport_gpio_set_blue_led(LED_ON);
			vTaskDelay(pdMS_TO_TICKS(500));
			lzport_gpio_set_blue_led(LED_OFF);
		} else {
			// Task Notify timed out, meaning the deferral ticket task does not work as expected
			lzport_gpio_set_status_led(LED_FAIL, LED_ON);
		}
	}
}

TaskHandle_t get_led_task_handle(void)
{
	return led_task_handle;
}
