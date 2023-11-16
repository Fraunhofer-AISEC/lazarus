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
#include "lzport_debug_output.h"
#include "lzport_rng.h"
#include "lz_power_handler.h"

static status_t get_random_data(void *data, size_t size);

// Taken from fsl_rng.c Copyright NXP, SPDX-License-Identifier: BSD-3-Clause
static void rng_accumulateEntropy(RNG_Type *base)
{
	uint32_t minChiSq;
	uint32_t maxChiSq;

	/* Steps to accumulate entropy, more info can be found in LPC55SXX UM*/

	/* Select fourth clock on which to compute CHI SQUARE statistics*/
	base->COUNTER_CFG =
		(base->COUNTER_CFG & ~RNG_COUNTER_CFG_CLOCK_SEL_MASK) | RNG_COUNTER_CFG_CLOCK_SEL(4U);

	/* Activate CHI computing */
	base->ONLINE_TEST_CFG = RNG_ONLINE_TEST_CFG_ACTIVATE(1U);

	/* Read min chi squared value, on power on should be higher than max chi squared value */
	minChiSq = ((base->ONLINE_TEST_VAL & RNG_ONLINE_TEST_VAL_MIN_CHI_SQUARED_MASK) >>
				RNG_ONLINE_TEST_VAL_MIN_CHI_SQUARED_SHIFT);

	/* Read max chi squared value */
	maxChiSq = ((base->ONLINE_TEST_VAL & RNG_ONLINE_TEST_VAL_MAX_CHI_SQUARED_MASK) >>
				RNG_ONLINE_TEST_VAL_MAX_CHI_SQUARED_SHIFT);

	/* Wait until minChiSq decreases and become smaller than maxChiSq*/
	while (minChiSq > (maxChiSq - 1U)) {
		maxChiSq = ((base->ONLINE_TEST_VAL & RNG_ONLINE_TEST_VAL_MAX_CHI_SQUARED_MASK) >>
					RNG_ONLINE_TEST_VAL_MAX_CHI_SQUARED_SHIFT);
		minChiSq = ((base->ONLINE_TEST_VAL & RNG_ONLINE_TEST_VAL_MIN_CHI_SQUARED_MASK) >>
					RNG_ONLINE_TEST_VAL_MIN_CHI_SQUARED_SHIFT);
	}
}

/**
 * Initializes the True Random Number Generator
 */
void lzport_rng_init(void)
{
	uint32_t maxChiSq, tmpShift4x;

	/* Clear ring oscilator disable bit*/
#if defined(DICEPP) || defined(LZ_CORE)
	PMC->PDRUNCFGCLR0 = PMC_PDRUNCFG0_PDEN_RNG_MASK;
#else
	lz_power_init_rng_ring_oscillator_nse();
#endif
#if !(defined(FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL) && FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL)
	CLOCK_EnableClock(kCLOCK_Rng);
#endif /* FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL */

#if !(defined(FSL_SDK_DISABLE_DRIVER_RESET_CONTROL) && FSL_SDK_DISABLE_DRIVER_RESET_CONTROL)
	/* Reset the module. */
	RESET_PeripheralReset(kRNG_RST_SHIFT_RSTn);
#endif /* FSL_SDK_DISABLE_DRIVER_RESET_CONTROL */

	/* Turn on CHI Squared test */
	/* Activate CHI computing and wait until min chi squared become smaller than max chi squared */
	rng_accumulateEntropy(RNG);

	maxChiSq = ((RNG->ONLINE_TEST_VAL & RNG_ONLINE_TEST_VAL_MAX_CHI_SQUARED_MASK) >>
				RNG_ONLINE_TEST_VAL_MAX_CHI_SQUARED_SHIFT);

	/* When maxChiSq is bigger than 4 its assumed there is not enough entropy and previous steps are repeated */
	/* When maxChiSq is 4 or less initialization is complete and random number can be read*/
	while (maxChiSq > 4U) {
		/* Deactivate CHI coputing to reset*/
		RNG->ONLINE_TEST_CFG = RNG_ONLINE_TEST_CFG_ACTIVATE(0);

		/* read Shift4x register, if is less than 7 increment it and then start accumulating entropy again */
		tmpShift4x =
			((RNG->COUNTER_CFG & RNG_COUNTER_CFG_SHIFT4X_MASK) >> RNG_COUNTER_CFG_SHIFT4X_SHIFT);
		if (tmpShift4x < 7U) {
			tmpShift4x++;
			RNG->COUNTER_CFG = (RNG->COUNTER_CFG & ~RNG_COUNTER_CFG_SHIFT4X_MASK) |
							   RNG_COUNTER_CFG_SHIFT4X(tmpShift4x);
		}
		rng_accumulateEntropy(RNG);

		maxChiSq = ((RNG->ONLINE_TEST_VAL & RNG_ONLINE_TEST_VAL_MAX_CHI_SQUARED_MASK) >>
					RNG_ONLINE_TEST_VAL_MAX_CHI_SQUARED_SHIFT);
	}

	VERB("RNG initialization successful\n");
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
#if !(defined(FSL_SDK_DISABLE_DRIVER_RESET_CONTROL) && FSL_SDK_DISABLE_DRIVER_RESET_CONTROL)
	/* Reset the module. */
	RESET_PeripheralReset(kRNG_RST_SHIFT_RSTn);
#endif /* FSL_SDK_DISABLE_DRIVER_RESET_CONTROL */

#if !(defined(FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL) && FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL)
	CLOCK_DisableClock(kCLOCK_Rng);
#endif /* FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL */

	VERB("RNG de-initialization successful\n");
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
		VERB("RNG generating random data successful\n");
		result = LZ_SUCCESS;
	} else {
		VERB("WARN: Generating random data not successful. Reinitialing RNG..\n");

		// Try to re-init the TRNG
		lzport_rng_init();

		// Try again
		if (kStatus_Success == get_random_data(data, size)) {
			VERB("RNG generating random data now successful\n");
			result = LZ_SUCCESS;
		} else {
			ERROR("Generating random data failed\n");
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
