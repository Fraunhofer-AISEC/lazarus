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

#ifndef LZPORT_FREERTOS_DELAY_LZPORT_DELAY_H_
#define LZPORT_FREERTOS_DELAY_LZPORT_DELAY_H_

/** Option 1 for applications without RTOS: Use the LPC55S69 SysTick directly */
#define SYSTICK_LPC55S69 0

/** Option 2 for application running FreeRTOS: Use FreeRTOS tick functions */
#define SYSTICK_FREERTOS 1

/** Define one of the options specified above here */
#define SELECTED_TICK_MS SYSTICK_FREERTOS

uint32_t lzport_get_tick_ms(void);
void lzport_delay(uint32_t time_ms);
void lzport_init_systick_1khz(void);
void lzport_deinit_systick(void);

#endif /* LZPORT_FREERTOS_DELAY_LZPORT_DELAY_H_ */
