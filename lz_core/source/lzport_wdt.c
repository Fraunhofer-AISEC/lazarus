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

#include "lzport_debug_output/lzport_debug_output.h"
#include "board.h"
#include <stdbool.h>
#include "lzport_wdt.h"
#include "exception_handler.h"

/** First word of refresh sequence */
#define WWDT_FIRST_WORD_OF_REFRESH (0xAAU)
/** Second word of refresh sequence */
#define WWDT_SECOND_WORD_OF_REFRESH (0x55U)

#define WWDT_MAX_PERIOD_S 3600UL

/**
 * 1 / (CLK_FREQ / (PRESCALE * 4)) =
 * 1 / (1 MHz / (64 * 4)) =
 * 0,000256s * WWDT_MULTIPLE_BUF_TICKS =
 * 0,26s Warning Time
 */
#define WWDT_MULTIPLE_BUF_TICKS (1023UL)

/** Indicates how many times the watchdog must be reloaded internally to reach the specified time */
static uint32_t wwdt_multiple;

/** wwdt_last period that actually leads to the reset if the watchdog was not reloaded */
static uint32_t wwdt_last;

static uint32_t wdt_freq_hz;

/**
 * Checks whether a watchdog reset was the cause of the wwdt_last device
 * reset.
 * @returns true if watchdog reset occured, otherwise false
 */
bool lzport_last_reset_awdt(void)
{
	// Check if reset was due to Watchdog
	if (WWDT->MOD & (WWDT_MOD_WDTOF_MASK)) {
		dbgprint(DBG_AWDT, "INFO: The microcontroller was reset because of a watchdog "
						   "reset\n");

		// Clean the time out flag.
		uint32_t reg = (WWDT->MOD & (~WWDT_MOD_WDINT_MASK));
		reg &= ~WWDT_MOD_WDTOF_MASK;
		WWDT->MOD = reg;

		return true;
	}

	return false;
}

/**
 * Initializes the watchdog with the specified timeout.
 * @param timeout_s The timeout in seconds
 */
void lzport_wdt_init(uint32_t timeout_s)
{
	dbgprint(DBG_AWDT, "INFO: Initializing Watchdog Timer..\n");

	// If timeout is higher than maximum WDT timeout, the watchdog is reloaded internally
	// via the WWDT Warning Interrupt until the specified limit is reached
	wwdt_multiple = timeout_s / WWDT_MAX_PERIOD_S;
	wwdt_last = timeout_s % WWDT_MAX_PERIOD_S;
	dbgprint(DBG_AWDT, "INFO: wwdt_multiple = %d, wwdt_last = %d\n", wwdt_multiple, wwdt_last);

	// Enable FRO 1M clock for WWDT module.
	SYSCON->CLOCK_CTRL |= SYSCON_CLOCK_CTRL_FRO1MHZ_CLK_ENA_MASK;

	// Set clock divider for WWDT clock source. 64 is the maximum possible divider
	// NOTE: In the user manual, a wrong value of 256 is specified as the maximum timeout.
	CLOCK_SetClkDiv(kCLOCK_DivWdtClk, 64U, true);

	// The WDT divides the input frequency into it by 4
	wdt_freq_hz = CLOCK_GetFreq(kCLOCK_WdtClk) / 4;

	CLOCK_EnableClock(kCLOCK_Wwdt);

	RESET_PeripheralReset(kWWDT_RST_SHIFT_RSTn);

	// Watchdog is enabled and resets device when it expired
	WWDT->MOD |= WWDT_MOD_WDEN(true) | WWDT_MOD_WDRESET(true);
	// Windowing is not active
	WWDT->WINDOW = WWDT_WINDOW_WINDOW(0xFFFFFFU);

	if (wwdt_multiple) {
		WWDT->TC = WWDT_TC_COUNT(wdt_freq_hz * WWDT_MAX_PERIOD_S + WWDT_MULTIPLE_BUF_TICKS);
		WWDT->WARNINT = WWDT_WARNINT_WARNINT(WWDT_MULTIPLE_BUF_TICKS);
		wwdt_multiple--;

		// Enable warning IRQ. The warning IRQ is used for internal resets if the configured time
		// exceeds the maximum WWDG time TODO check if necessary
		svc_enable_wdg_irq();
	} else {
		WWDT->TC = WWDT_TC_COUNT(wdt_freq_hz * wwdt_last);
		WWDT->WARNINT = WWDT_WARNINT_WARNINT(0);

		// Disable warning IRQ because it is not necessary if the AWDT timeout is smaller than the
		// maximum WWDG timeout TODO check if necessary, the IRQ cannot be triggered anymore if the
		// watchdog resets so it can be just left enabled
		svc_disable_wdg_irq();
	}

	// Refresh watchdog
	uint32_t primaskValue = DisableGlobalIRQ();
	WWDT->FEED = WWDT_FIRST_WORD_OF_REFRESH;
	WWDT->FEED = WWDT_SECOND_WORD_OF_REFRESH;
	EnableGlobalIRQ(primaskValue);

	// This WDPROTECT bit can be set once by software and is only cleared by a reset
	if ((WWDT->MOD & WWDT_MOD_WDPROTECT_MASK) == 0U) {
		// Set the WDPROTECT bit after the Feed Sequence (0xAA, 0x55) with 3 WDCLK delay
		uint32_t DelayUs = 3000000UL / CLOCK_GetFreq(kCLOCK_WdtClk) + 1U;
		// TODO clean solution. This code waits longer than 3 WDCLK
		for (uint32_t i = 0; i < DelayUs; i++) {
			__asm("NOP");
		}

		WWDT->MOD |= WWDT_MOD_WDPROTECT(false);
	}

	dbgprint(DBG_AWDT, "INFO: WDT Successfully initialized\n");
}

/**
 * Reloads the watchdog with the specified timeout. The maximum value for the timeout is 3600s.
 * If the value is higher, it is limited to this value.
 * @param timeout_s The timeout in seconds
 */
void lzport_wdt_reload(uint32_t timeout_s)
{
	// If timeout is higher than maximum WDT timeout, the watchdog is reloaded internally
	// via the WWDT Warning Interrupt until the specified limit is reached
	wwdt_multiple = timeout_s / WWDT_MAX_PERIOD_S;
	wwdt_last = timeout_s % WWDT_MAX_PERIOD_S;
	dbgprint(DBG_AWDT, "INFO: WDT Reload - wwdt_multiple = %d, wwdt_last = %d\n", wwdt_multiple,
			 wwdt_last);

	// The WDT divides the input frequency into it by 4
	uint32_t wdt_freq_hz = CLOCK_GetFreq(kCLOCK_WdtClk) / 4;

	// Set new timeout
	if (wwdt_multiple) {
		WWDT->TC = WWDT_TC_COUNT(wdt_freq_hz * WWDT_MAX_PERIOD_S + WWDT_MULTIPLE_BUF_TICKS);
		WWDT->WARNINT = WWDT_WARNINT_WARNINT(WWDT_MULTIPLE_BUF_TICKS);
		wwdt_multiple--;

		// TODO check if necessary
		svc_enable_wdg_irq();
	} else {
		WWDT->TC = WWDT_TC_COUNT(wdt_freq_hz * wwdt_last);
		WWDT->WARNINT = WWDT_WARNINT_WARNINT(0);

		// TODO check if necessary
		svc_disable_wdg_irq();
	}

	// Disable the global interrupt to protect refresh sequence
	uint32_t primaskValue = 0U;
	primaskValue = DisableGlobalIRQ();
	WWDT->FEED = WWDT_FIRST_WORD_OF_REFRESH;
	WWDT->FEED = WWDT_SECOND_WORD_OF_REFRESH;
	EnableGlobalIRQ(primaskValue);

	dbgprint(DBG_AWDT, "INFO: WDT successfully reloaded!\n");
}

__attribute__((used)) __attribute__((section(".text_Flash_IRQ"))) void WDT_BOD_IRQHandler(void)
{
	// If only the warning interrupt triggered, this is because of the internal reset
	// system that enabled arbitrarily long intervals
	if ((WWDT->MOD & WWDT_MOD_WDINT_MASK) && !(WWDT->MOD & WWDT_MOD_WDTOF_MASK)) {
		// Clear the warning flag by writing a 1
		WWDT->MOD |= WWDT_MOD_WDINT_MASK;

		// If the remaining timeout is still higher than the WDT maximum: Set to max and
		// decrement the wwdt_multiple counter
		if (wwdt_multiple) {
			wwdt_multiple--;
			WWDT->TC = WWDT_TC_COUNT(wdt_freq_hz * WWDT_MAX_PERIOD_S + WWDT_MULTIPLE_BUF_TICKS);
			WWDT->WARNINT = WWDT_WARNINT_WARNINT(WWDT_MULTIPLE_BUF_TICKS);

			// Disable the global interrupt to protect refresh sequence
			// DisableGlobalIRQ cannot be called
			uint32_t primaskValue = 0U;
			__ASM volatile("MRS %0, primask" : "=r"(primaskValue)::"memory");
			__ASM volatile("cpsid i" : : : "memory");

			WWDT->FEED = WWDT_FIRST_WORD_OF_REFRESH;
			WWDT->FEED = WWDT_SECOND_WORD_OF_REFRESH;
			// Enable Global IRQ (EnableGlobalIRQ cannot be called)
			__ASM volatile("MSR primask, %0" : : "r"(primaskValue) : "memory");
		}
		// If the timeout is smaller, disable the warning interrupt and set the timeout
		else {
			WWDT->TC = WWDT_TC_COUNT(wdt_freq_hz * wwdt_last);
			WWDT->WARNINT = WWDT_WARNINT_WARNINT(0);

			// Disable the global interrupt to protect refresh sequence
			// DisableGlobalIRQ cannot be called
			uint32_t primaskValue = 0U;
			__ASM volatile("MRS %0, primask" : "=r"(primaskValue)::"memory");
			__ASM volatile("cpsid i" : : : "memory");
			WWDT->FEED = WWDT_FIRST_WORD_OF_REFRESH;
			WWDT->FEED = WWDT_SECOND_WORD_OF_REFRESH;
			// Enable Global IRQ (EnableGlobalIRQ cannot be called)
			__ASM volatile("MSR primask, %0" : : "r"(primaskValue) : "memory");

			// Disable the warning interrupt, as now only an AWDT reset will prevent the device
			// from rebooting TODO check if necessary
			// NVIC_DisableIRQ cannot be called
			NVIC->ICER[(((uint32_t)WDT_BOD_IRQn) >> 5UL)] =
				(uint32_t)(1UL << (((uint32_t)WDT_BOD_IRQn) & 0x1FUL));
			__DSB();
			__ISB();
		}
	}
}
