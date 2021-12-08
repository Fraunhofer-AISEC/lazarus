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

#include "string.h"
#include "stdio.h"
#include "stdint.h"

#include "FreeRTOS.h"
#include "task.h"

#include "lz_config.h"
#include "lzport_debug_output/lzport_debug_output.h"
#include "benchmark.h"
#include "lz_awdt.h"
#include "sensor.h"
#include "net.h"

#if (1 == FREERTOS_BENCHMARK_ACTIVE)

#define MAX_NUM_TASKS 10

volatile uint32_t hf_timer_ticks; // TODO delete?
static TaskHandle_t benchmark_task_handle = NULL;

static void print_benchmark(void);
static void print_benchmark_vs_reference(void);

void benchmark_task(void *params)
{
	benchmark_task_handle = xTaskGetCurrentTaskHandle();

	TickType_t last_wake_time = xTaskGetTickCount();

	for (;;) {
		// Wait until benchmark is triggerd
		ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

		print_benchmark();
	}
}

#include "fsl_ctimer.h"

void freertos_benchmark_init_ticks(void)
{
	ctimer_config_t config;

	// Enable FRO 1M clock for WWDT module.
	//SYSCON->CLOCK_CTRL |= SYSCON_CLOCK_CTRL_FRO1MHZ_CLK_ENA_MASK;

	CLOCK_AttachClk(kFRO_HF_to_CTIMER4);

	CTIMER_GetDefaultConfig(&config);

	config.prescale = 95;

	CTIMER_Init(CTIMER4, &config);

	CTIMER_StartTimer(CTIMER4);
}

uint32_t freertos_benchmark_get_ticks(void)
{
	return CTIMER_GetTimerCountValue(CTIMER4);
}

static TaskStatus_t task_status_array[MAX_NUM_TASKS];

static void print_benchmark(void)
{
	// Currently, up to 10 tasks are supported
	volatile UBaseType_t number_of_tasks;
	float stats_as_percentage;
	static uint32_t iteration = 0;

	memset(task_status_array, 0x0, sizeof(TaskStatus_t) * MAX_NUM_TASKS);

	// Take a snapshot of the number of tasks in case it changes while this function is executing
	number_of_tasks = uxTaskGetNumberOfTasks();

	if (number_of_tasks > MAX_NUM_TASKS) {
		dbgprint(DBG_WARN, "Warning: number of tasks higher than MAX_NUM_TASKS constant. "
						   "Benchmark will not be printed");
		return;
	}

	// Generate raw status information about each task
	uint32_t runtime;
	number_of_tasks = uxTaskGetSystemState(task_status_array, number_of_tasks, &runtime);

#if (1 != FREERTOS_BENCHMARK_DEFERRAL_OUTPUT)
	dbgprint(DBG_INFO, "Runtime Statistics Iteration %d (total runtime = %dms)\n", ++iteration,
			 runtime / 1000);
#endif

	// Avoid divide by zero errors
	if (runtime > 0) {
		// Iterate through each position in the task_status_array, format raw data to ASCII
		// and print it
		for (uint32_t i = 0; i < number_of_tasks; i++) {
			// Percentage of the total run time the task has used
			stats_as_percentage =
				((float)task_status_array[i].ulRunTimeCounter / (float)runtime) * 100.0;

#if (1 == FREERTOS_BENCHMARK_DEFERRAL_OUTPUT)
			if (strcmp(task_status_array[i].pcTaskName, "ADT ") == 0) {
				// TODO this is very quick and dirty because the debug console cannot print floats
				dbgprint(
					DBG_INFO, "%d,%d.%03d,%d\n", ++iteration, (uint32_t)stats_as_percentage,
					(uint32_t)((stats_as_percentage - (uint32_t)stats_as_percentage) * 1000.0f),
					task_status_array[i].ulRunTimeCounter / 1000);
			}
#else
			// TODO this is very quick and dirty because the debug console cannot print floats
			dbgprint(DBG_INFO, "%s      %d.%03d%%    (%dms)\n", task_status_array[i].pcTaskName,
					 (uint32_t)stats_as_percentage,
					 (uint32_t)((stats_as_percentage - (uint32_t)stats_as_percentage) * 1000.0f),
					 task_status_array[i].ulRunTimeCounter / 1000);
#endif
		}
	} else {
		dbgprint(DBG_WARN, "WARN: benchmark - runtime is zero\n");
	}
}

TaskHandle_t get_benchmark_task_handle(void)
{
	return benchmark_task_handle;
}

#endif
