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
#include "lzport_memory/lzport_memory.h"
#include "lzport_debug_output/lzport_debug_output.h"
#include "lzport_gpio/lzport_gpio.h"
#include "lz_common/lz_common.h"
#include "lz_net/lz_net.h"
#include "lz_awdt.h"
#include "sensor.h"

static TaskHandle_t net_task_handle = NULL;

void net_task(void *params)
{
#if (1 == LZ_DBG_TRACE_BOOT_ACTIVE_WO_TICKET)
	lzport_gpio_toggle_trace();
	vTaskDelay(pdMS_TO_TICKS(2000));
	NVIC_SystemReset();
#endif

	// Setup ESP8266, connect to Wi-Fi AP
	if (LZ_SUCCESS != lz_net_init()) {
		dbgprint(DBG_ERR, "ERROR: Could not initialize network connection. Waiting forever..\n");
		for (;;)
			;
	}

	// Send AliasID certificate
	if (LZ_SUCCESS != lz_net_send_alias_id_cert()) {
		dbgprint(DBG_WARN, "ERROR: WARN: Updating AliasID cert in backend not successful. Waiting "
						   "forever..\n");
		for (;;)
			;
	}

	// Fetch boot ticket for next boot
	if (lz_net_refresh_boot_ticket() != LZ_SUCCESS) {
		// TODO Error handling: in regular intervals, it should be tried again to get a boot ticket
		dbgprint(DBG_WARN, "WARN: Could not retrieve a boot ticket from backend.\n");
	}

	lzport_gpio_set_status_led(LED_OK, LED_ON);

	// TODO FW Update ONLY on request
	// 	if (lz_net_fw_update(LZ_CORE_UPDATE) == LZ_SUCCESS)
	// 	{
	// 		if (lz_set_boot_mode_request(LZ_CPATCHER) != LZ_SUCCESS)
	// 		{
	// 			dbgprint(DBG_WARN, "WARN: Failed to set boot mode request\n");
	// 		}
	// 		dbgprint(DBG_INFO, "INFO: Rebooting to apply update\n");
	// 		vTaskDelay(pdMS_TO_TICKS(100));
	// 		NVIC_SystemReset();
	// 	}
	// 	else
	// 	{
	// 		dbgprint(DBG_INFO, "INFO: Failed to download update from hub\n");
	// 	}

	// Notify AWDT task that network connection is established
	xTaskNotifyGive(get_task_awdt_handle());

#if (RUN_IOT_SENSOR_DEMO == 1)
	xTaskNotifyGive(get_sensor_task_handle());
#endif

	for (;;) {
		// TODO regularly check the network status and re-establish connection if lost
		vTaskDelay(pdMS_TO_TICKS(portMAX_DELAY));
	}
}

TaskHandle_t get_net_task_handle(void)
{
	return net_task_handle;
}
