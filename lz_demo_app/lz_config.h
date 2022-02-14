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

#ifndef LZ_CONFIG_H_
#define LZ_CONFIG_H_

// Signalize that FreeRTOS is available and can be used for certain functions
#define FREERTOS_AVAILABLE 1

// Do not edit! These are just the debug output levels
#define DBG_NONE (0x0U)
#define DBG_ERR (0x1U)
#define DBG_WARN (0x2U)
#define DBG_INFO (0x4U)
#define DBG_VERB (0x8U)
#define DBG_NW (0x10U)
#define DBG_SENSOR (0x20U)

// Set the desired debug output here (The definitions from above can be OR'ed)
#define LZ_DBG_LEVEL (DBG_ERR | DBG_WARN | DBG_INFO)

// Toggle the GPIO trace output to measure the boot time
// TODO delete only for testing
#define LZ_DBG_TRACE_BOOT_ACTIVE_WO_TICKET 0
#define LZ_DBG_TRACE_BOOT_ACTIVE_W_TICKET 0
#define LZ_DBG_TRACE_DEFERRAL_ACTIVE 0
#define LZ_DBG_NETWORK 0

#define FREERTOS_BENCHMARK_ACTIVE 0
#define FREERTOS_BENCHMARK_DEFERRAL_OUTPUT 0

#define RUN_IOT_SENSOR_DEMO 0

#endif /* LZ_CONFIG_H_ */
