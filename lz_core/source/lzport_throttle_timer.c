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
#include <stdbool.h>
#include "fsl_common.h"
#include "fsl_ctimer.h"

#define CTIMER CTIMER3
#define CTIMER_CLK kFRO_HF_to_CTIMER3
#define CTIMER_MAT_OUT kCTIMER_Match_3
#define CTIMER_CLK_FREQ CLOCK_GetFreq(kCLOCK_CTmier3)

void lzport_throttle_timer_init()
{
	ctimer_config_t config;
	CLOCK_AttachClk(CTIMER_CLK);
	CTIMER_GetDefaultConfig(&config);
	CTIMER_Init(CTIMER, &config);
	CTIMER_Reset(CTIMER);
}

/**
 * The throttling counter will start counting up to
 * timeout_s seconds. Once it has reached this value,
 * it will reset itself back to 0 and stop counting.
 *
 * To start a new counting, call this function again
 * with the appropriate timeout.
 */
static ctimer_match_config_t match_config;
void lzport_throttle_timer_start(uint32_t timeout_s)
{
	match_config.enableCounterReset = true;
	match_config.enableCounterStop = true;
	match_config.outControl = kCTIMER_Output_NoAction;
	match_config.outPinInitState = false;
	match_config.enableInterrupt = false;

	match_config.matchValue = CTIMER_CLK_FREQ * timeout_s;

	CTIMER_SetupMatch(CTIMER, CTIMER_MAT_OUT, &match_config);
	CTIMER_StartTimer(CTIMER);
}

bool lzport_throttle_timer_is_active()
{
	uint32_t timer_val = CTIMER_GetTimerCountValue(CTIMER);
	return ((0 < timer_val) && (timer_val < match_config.matchValue));
}
