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

#ifndef lzport_DEBUG_OUTPUT_H
#define lzport_DEBUG_OUTPUT_H

#include "lz_config.h"

#ifndef LZ_DBG_LEVEL
#error Error: LZ_DBG_LEVEL must be defined in lz_config.h
#endif

/* Only include the debug console if needed */
#if (LZ_DBG_LEVEL > DBG_NONE)
#include "fsl_debug_console.h"
#endif

/* PRINTF is the LPC55S69 version of printf. Provide your own version here if necessary */
#define dbgprint(lvl, fmt, ...)                                                                    \
	do {                                                                                           \
		if (LZ_DBG_LEVEL & (uint32_t)lvl)                                                          \
			PRINTF(fmt, ##__VA_ARGS__);                                                            \
	} while (0)

/* This is the initialization of the debug usart which is excluded if the debug output is not needed */
#define lzport_init_debug()                                                                        \
	do {                                                                                           \
		if (LZ_DBG_LEVEL > 0)                                                                      \
			BOARD_InitDebugConsole();                                                              \
	} while (0)

#if (LZ_DBG_LEVEL > DBG_NONE)
void dbgprint_data(uint8_t *data, uint32_t len, char *info);
#else
#define dbgprint_data(data, len, info)
#endif

#endif /* lzport_DEBUG_OUTPUT_H */
