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
#include "fsl_rng.h"
#include "lz_config.h"
#include "lzport_debug_output/lzport_debug_output.h"
#include "lzport_rng/lzport_rng.h"
#include "lz_trustzone_handler/lz_power_handler.h"

static status_t get_random_data(void *data, size_t size);

/**
 * Initializes the True Random Number Generator
 */
void lzport_rng_init(void)
{
	/* Clear ring oscilator disable bit*/
#if defined(DICEPP) || defined(LZ_CORE)
	PMC->PDRUNCFGCLR0 = PMC_PDRUNCFG0_PDEN_RNG_MASK;
#else
	lz_power_init_rng_ring_oscillator_nse();
#endif
#if !(defined(FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL) && FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL)
	CLOCK_EnableClock(kCLOCK_Rng);
#endif /* FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL */
	/* Clear POWERDOWN bit to enable RNG */
	RNG->POWERDOWN &= ~RNG_POWERDOWN_POWERDOWN_MASK;

	dbgprint(DBG_VERB, "INFO: RNG initialization successful\n");
}

/**
 * Deinitializes the True Random Number Generator
 */
void lzport_rng_deinit(void)
{
	/* Set ring oscillator disable bit*/
#if defined(DICEPP) || defined(LZ_CORE)
	PMC->PDRUNCFGSET0 = PMC_PDRUNCFG0_PDEN_RNG_MASK;
#else
	lz_power_deinit_rng_ring_oscillator_nse();
#endif
	/* Set POWERDOWN bit to disable RNG */
	RNG->POWERDOWN |= RNG_POWERDOWN_POWERDOWN_MASK;
#if !(defined(FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL) && FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL)
	CLOCK_DisableClock(kCLOCK_Rng);
#endif /* FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL */

	dbgprint(DBG_VERB, "INFO: RNG de-initialization successful\n");
}

/**
 * Gets random data from the True Random Number Generator
 *
 * @param data buffer to be filled with random data
 * @param size size of the buffer
 */
LZ_RESULT lzport_rng_get_random_data(void *data, size_t size)
{
	LZ_RESULT result = LZ_ERROR;

	if (kStatus_Success == get_random_data(data, size)) {
		dbgprint(DBG_VERB, "INFO: RNG generating random data successful\n");
		result = LZ_SUCCESS;
	} else {
		dbgprint(DBG_VERB, "WARN: Generating random data not successful. Reinitialing RNG..\n");

		// Try to re-init the TRNG
		lzport_rng_init();

		// Try again
		if (kStatus_Success == get_random_data(data, size)) {
			dbgprint(DBG_VERB, "INFO: RNG generating random data now successful\n");
			result = LZ_SUCCESS;
		} else {
			dbgprint(DBG_ERR, "ERROR: Generating random data failed\n");
		}
	}

	return result;
}

status_t get_random_data(void *data, size_t size)
{
#if defined(DICEPP) || defined(LZ_CORE)
	return RNG_GetRandomData(RNG, data, size);
#else
	status_t result = kStatus_Fail;
	uint32_t random32;
	uint32_t randomSize;
	uint8_t *pRandom;
	uint8_t *pData = (uint8_t *)data;
	uint32_t i;

	if (!lz_power_is_ring_oscillator_enabled_nse()) {
		do {
			/* Read Entropy.*/
			random32 = RNG->RANDOM_NUMBER;
			pRandom = (uint8_t *)&random32;

			if (size < sizeof(random32)) {
				randomSize = size;
			} else {
				randomSize = sizeof(random32);
			}

			for (i = 0; i < randomSize; i++) {
				*pData++ = *pRandom++;
			}

			size -= randomSize;
		} while (size > 0);

		result = kStatus_Success;
	}

	return result;
#endif
}
