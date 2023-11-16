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

#include "fsl_common.h"

/**
 * Millisecond counter
 */
static volatile uint32_t tick_ms = 0;

/**
 * Returns the current tick value in milliseconds
 *
 * @retval tick value in milliseconds
 */
uint32_t lzport_get_tick_ms(void)
{
	return tick_ms;
}

/**
 * Wait for the specified amount of milliseconds
 * @param time_ms The time to wait
 */
void lzport_delay(uint32_t time_ms)
{
	uint32_t deadline = lzport_get_tick_ms() + time_ms;
	while (deadline >= lzport_get_tick_ms())
		;
}

/**
 * Initialize systick and systick IRQ with a frequency of 1 kHz
 *
 * @retval None
 */
void lzport_init_systick_1khz(void)
{
	SysTick_Config(SystemCoreClock / 1000);
}

void lzport_deinit_systick(void)
{
	SysTick->CTRL = 0x0;
}

/**
 * SysTick Handler Callback
 *
 * @retval None
 */
void SysTick_Handler(void)
{
	tick_ms++;
}
