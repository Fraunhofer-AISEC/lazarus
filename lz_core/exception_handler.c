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

#if (__ARM_FEATURE_CMSE & 1) == 0
#error "Need ARMv8-M security extensions"
#elif (__ARM_FEATURE_CMSE & 2) == 0
#error "Compile with --cmse"
#endif

#include <stdio.h>
#include "lz_config.h"
#include "lzport_debug_output.h"
#include "arm_cmse.h"
#include "board.h"
#include "exception_handler.h"

__attribute__((section(".text_Flash_IRQ"))) void HardFault_Handler(void) __attribute__((naked));
__attribute__((section(".text_Flash_IRQ"))) void SVC_Handler(void) __attribute__((naked));

// This function is used for minimal debug output from the handler. The normal debug output
// cannot be used, as it is placed in sercure non-privileged flash.
#if (LZ_DBG_LEVEL > DBG_NONE)
__attribute__((section(".text_Flash_IRQ"))) void
dbgprint_exception(USART_Type *base, const uint8_t *data, size_t length)
{
	// Check if txFIFO is enabled
	if (!(base->FIFOCFG & USART_FIFOCFG_ENABLETX_MASK)) {
		return;
	}
	for (; length > 0; length--) {
		// Loop until FIFO has space for new data
		while (!(base->FIFOSTAT & USART_FIFOSTAT_TXNOTFULL_MASK))
			;
		base->FIFOWR = *data;
		data++;
	}
	// Wait for transfer to be finished
	while (!(base->STAT & USART_STAT_TXIDLE_MASK))
		;
}
#endif

void HardFault_Handler(void)
{
	__asm volatile(" tst lr, #4                                                \n"
				   " ite eq                                                    \n"
				   " mrseq r0, msp                                             \n"
				   " mrsne r0, psp                                             \n"
				   " ldr r1, [r0, #24]                                         \n"
				   " ldr r2, handler2_address_const                            \n"
				   " bx r2                                                     \n"
				   " handler2_address_const: .word hardfault_handler_c		    \n");
}

__attribute__((used)) __attribute__((section(".text_Flash_IRQ"))) void
hardfault_handler_c(uint32_t *fault_stack_addr)
{
	volatile uint32_t r0;
	volatile uint32_t r1;
	volatile uint32_t r2;
	volatile uint32_t r3;
	volatile uint32_t r12;
	volatile uint32_t lr;
	volatile uint32_t psr;
	volatile uint32_t pc;

	r0 = fault_stack_addr[0];
	r1 = fault_stack_addr[1];
	r2 = fault_stack_addr[2];
	r3 = fault_stack_addr[3];

	r12 = fault_stack_addr[4];
	lr = fault_stack_addr[5];
	pc = fault_stack_addr[6];
	psr = fault_stack_addr[7];

#if (LZ_DBG_LEVEL > DBG_NONE)
	char buf[200];
	snprintf(
		buf, sizeof(buf),
		"rFATAL: Secure Hardfault: r0=%lx\nr1=%lx\nr2=%lx\nr3=%lx\nr12=%lx\nlr=%lx\npsr=%lx\npc=%lx\n",
		r0, r1, r2, r3, r12, lr, psr, pc);
	dbgprint_exception(USART0, (uint8_t *)buf, sizeof(buf));
#endif

	for (;;)
		;
}

void SVC_Handler(void)
{
	__asm volatile("	tst lr, #4										\n"
				   "	ite eq											\n"
				   "	mrseq r0, msp									\n"
				   "	mrsne r0, psp									\n"
				   "	ldr r1, svchandler_address_const				\n"
				   "	bx r1											\n"
				   "													\n"
				   "	.align 4										\n"
				   "svchandler_address_const: .word svc_handler_c      \n");
}

__attribute__((section(".text_Flash_IRQ"))) __STATIC_INLINE void __NVIC_SystemReset_Priv(void)
{
	__DSB(); /* Ensure all outstanding memory accesses included
	 buffered write are completed before reset */
	SCB->AIRCR =
		(uint32_t)((0x5FAUL << SCB_AIRCR_VECTKEY_Pos) | (SCB->AIRCR & SCB_AIRCR_PRIGROUP_Msk) |
				   SCB_AIRCR_SYSRESETREQ_Msk); /* Keep priority group unchanged */
	__DSB();								   /* Ensure completion of memory access */

	for (;;) /* wait until reset */
	{
		__NOP();
	}
}

__attribute__((section(".text_Flash_IRQ"))) __attribute__((used)) void
svc_handler_c(uint32_t *caller_stack_addr)
{
	uint32_t pc;
	uint8_t svc_num;

	// Register are stored on the stack in the following order: R0 - R3, R12, LR, PC, xPSR
	pc = caller_stack_addr[6];
	svc_num = ((uint8_t *)pc)[-2];

	switch (svc_num) {
	case SVC_WDG_IRQ_DISABLE:
		NVIC->ICER[(((uint32_t)WDT_BOD_IRQn) >> 5UL)] =
			(uint32_t)(1UL << (((uint32_t)WDT_BOD_IRQn) & 0x1FUL));
		__DSB();
		__ISB();
		break;
	case SVC_WDG_IRQ_ENABLE:
		NVIC->ISER[(((uint32_t)WDT_BOD_IRQn) >> 5UL)] =
			(uint32_t)(1UL << (((uint32_t)WDT_BOD_IRQn) & 0x1FUL));
		break;
	case SVC_SYSTEM_RESET:
		__NVIC_SystemReset_Priv();
		break;
	case SVC_PREPARE_SLEEP:
		SCB->SCR &= ~SCB_SCR_SLEEPDEEP_Msk; // Use sleep, not deep sleep
		break;
	default:
		break;
	}
}
