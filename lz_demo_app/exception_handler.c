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

#include <stdio.h>
#include "lz_config.h"
#include "lzport_debug_output.h"
#include "lzport_memory.h"

#define AHB_LAYERS_COUNT 19U

bool CFSR_Evaluate(SCB_Type *scb);
bool MFSR_Evaluate(SCB_Type *scb);
void BFSR_Evaluate(SCB_Type *scb);
void UFSR_Evaluate(SCB_Type *scb);
/*!
 * @brief HardFault handler. This handler can be called from both normal and secure world
 */
void HardFault_Handler(void)
{
	/* Handling SAU related secure faults */
	ERROR("\nEntering non-secure HardFault from demo app\n");

	if (SCB->CFSR & SCB_CFSR_MEMFAULTSR_Msk) {
		ERROR("CFSR MemManage fault\n");

		MFSR_Evaluate(SCB);
	}
	if (SCB->CFSR & SCB_CFSR_USGFAULTSR_Msk) {
		ERROR("CFSR Usage Fault\n");

		UFSR_Evaluate(SCB);
	}
	if (SCB->CFSR & SCB_CFSR_BUSFAULTSR_Msk) {
		ERROR("CFSR Bus Fault\n");

		BFSR_Evaluate(SCB);
	}

	for (;;)
		;
}

/**
 *  Evaluate bus fault register which is a part of the Configurable Fault Status Register
 */
void BFSR_Evaluate(SCB_Type *scb)
{
	if (scb->CFSR & SCB_CFSR_BFARVALID_Msk) {
		/* BFARVALID: BFAR contain valid address that caused secure violation */
		ERROR("Secure bus violation at address 0x%X.\n", SCB->BFAR);
	}
	if (scb->CFSR & SCB_CFSR_LSPERR_Msk) {
		ERROR("SCB->BFSR: Lazy state preservation error.");
	}
	if (scb->CFSR & SCB_CFSR_STKERR_Msk) {
		ERROR("SCB->BFSR: Stack error.");
	}
	if (scb->CFSR & SCB_CFSR_UNSTKERR_Msk) {
		ERROR("SCB->BFSR: Unstacking Error");
	}
	if (scb->CFSR & SCB_CFSR_PRECISERR_Msk) {
		/* PRECISERR: Instruction bus error on an instruction prefetch */
		ERROR("SCB->BFSR: PRECISERR fault: Precise data access error.\n");
	}
	if (scb->CFSR & SCB_CFSR_IBUSERR_Msk) {
		/* IBUSERR: Instruction bus error on an instruction prefetch */
		ERROR("SCB->BFSR: IBUSERR fault: Instruction bus error on an instruction prefetch.\n");
	}
}

/**
 * Evaluate MemManage Fault Status Register
 */
bool MFSR_Evaluate(SCB_Type *scb)
{
	bool exec_continue = false;
	if (scb->CFSR & SCB_CFSR_MMARVALID_Msk) {
		ERROR("SCB->MMFSR: MemManage MPU Access violation at address 0x%x\n", SCB->MMFAR);
		exec_continue = true;
	}
	if (scb->CFSR & SCB_CFSR_MLSPERR_Msk) {
		ERROR("SCB->MMFSR: MemManage lazy state preservation error flag\n");
	}
	if (scb->CFSR & SCB_CFSR_MSTKERR_Msk) {
		ERROR("SCB->MMFSR: MemManage stacking error flag\n");
	}
	if (scb->CFSR & SCB_CFSR_MUNSTKERR_Msk) {
		ERROR("SCB->MMFSR: MemManage unstacking error flag\n");
	}
	if (scb->CFSR & SCB_CFSR_DACCVIOL_Msk) {
		ERROR("SCB->MMFSR: MemManage Data access violation flag\n");
	}
	if (scb->CFSR & SCB_CFSR_IACCVIOL_Msk) {
		ERROR("SCB->MMFSR: MemManage Instruction access violation\n");
	}
	return exec_continue;
}

void UFSR_Evaluate(SCB_Type *scb)
{
	if (scb->CFSR & SCB_CFSR_DIVBYZERO_Msk) {
		ERROR("SCB->UFSR: Div By Zero Fault \n");
	}
	if (scb->CFSR & SCB_CFSR_UNALIGNED_Msk) {
		ERROR("SCB->UFSR: Unaligned Access Fault\n");
	}
	if (scb->CFSR & SCB_CFSR_STKOF_Msk) {
		ERROR("SCB->UFSR: Stack Overflow Fault\n");
	}
	if (scb->CFSR & SCB_CFSR_NOCP_Msk) {
		ERROR("SCB->UFSR: No Co-processor Fault\n");
	}
	if (scb->CFSR & SCB_CFSR_INVPC_Msk) {
		ERROR("SCB->UFSR: Invalid PC Fault\n");
	}
	if (scb->CFSR & SCB_CFSR_INVSTATE_Msk) {
		ERROR("SCB->UFSR: Invalid State Fault\n");
	}
	if (scb->CFSR & SCB_CFSR_UNDEFINSTR_Msk) {
		ERROR("SCB->UFSR: Undefined Instruction Flag\n");
	}
}
