/*
 * Copyright(c) 2022 Fraunhofer AISEC
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

#include "fsl_device_registers.h"
#include "fsl_power.h"
#include "lzport_debug_output.h"
#include "exception_handler.h"

void lzport_power_enter_sleep(void)
{
	VERB("Preparing sleep mode..\n");
	svc_prepare_sleep();
	VERB("Entering sleep\n");
	__WFI();
	VERB("Exit sleep mode..\n");
}

void lzport_power_init_rng_ring_oscillator(void)
{
	VERB("Initialing RNG ring oscillator..\n");
	PMC->PDRUNCFGCLR0 = PMC_PDRUNCFG0_PDEN_RNG_MASK;
	VERB("Initialized RNG ring oscillator..\n");
}

void lzport_power_deinit_rng_ring_oscillator(void)
{
	VERB("Deinitializing RNG ring oscillator..\n");
	PMC->PDRUNCFGSET0 = PMC_PDRUNCFG0_PDEN_RNG_MASK;
	VERB("Deinitialized RNG ring oscillator..\n");
}

bool lzport_power_is_ring_oscillator_enabled(void)
{
	return PMC->PDRUNCFG0 & PMC_PDRUNCFG0_PDEN_RNG_MASK;
}