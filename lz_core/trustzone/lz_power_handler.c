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

#include "arm_cmse.h"
#include "lzport_debug_output.h"
#include "pin_mux.h"
#include "fsl_device_registers.h"
#include "fsl_power.h"
#include "exception_handler.h"

#define FRO1M_BIT (1 << 4)
#define WAKEUP_SYS_BIT (1 << 0)

__attribute__((cmse_nonsecure_entry)) void lz_power_enter_sleep_nse(void)
{
	dbgprint(DBG_VERB, "INFO: Preparing sleep mode..\n");
	svc_prepare_sleep();
	dbgprint(DBG_VERB, "INFO: Entering sleep\n");
	__WFI();
	dbgprint(DBG_VERB, "INFO: Exit sleep mode..\n");
}

__attribute__((cmse_nonsecure_entry)) void lz_power_init_rng_ring_oscillator_nse(void)
{
	dbgprint(DBG_VERB, "INFO: Initialing RNG ring oscillator..\n");
	PMC->PDRUNCFGCLR0 = PMC_PDRUNCFG0_PDEN_RNG_MASK;
	dbgprint(DBG_VERB, "INFO: Initialized RNG ring oscillator..\n");
}

__attribute__((cmse_nonsecure_entry)) void lz_power_deinit_rng_ring_oscillator_nse(void)
{
	dbgprint(DBG_VERB, "INFO: Deinitializing RNG ring oscillator..\n");
	PMC->PDRUNCFGSET0 = PMC_PDRUNCFG0_PDEN_RNG_MASK;
	dbgprint(DBG_VERB, "INFO: Deinitialized RNG ring oscillator..\n");
}

__attribute__((cmse_nonsecure_entry)) bool lz_power_is_ring_oscillator_enabled_nse(void)
{
	return PMC->PDRUNCFG0 & PMC_PDRUNCFG0_PDEN_RNG_MASK;
}
