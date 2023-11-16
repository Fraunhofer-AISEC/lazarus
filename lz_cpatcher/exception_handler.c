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

#include "lzport_debug_output.h"
#include "arm_cmse.h"
#include "board.h"

#define AHB_LAYERS_COUNT 19U

typedef union {
	struct ahb_secure_fault_info {
		unsigned access_type : 2;
		unsigned reserved0 : 2;
		unsigned master_sec_level : 2;
		unsigned antipol_master_sec_level : 2;
		unsigned master_number : 4;
		unsigned reserved : 20;
	} fault_info;
	unsigned value;
} ahb_secure_fault_info_t;

bool CFSR_Evaluate(SCB_Type *scb);
bool MFSR_Evaluate(SCB_Type *scb);
void BFSR_Evaluate(SCB_Type *scb);
void UFSR_Evaluate(SCB_Type *scb);
/*!
 * @brief HardFault handler. This handler can be called from both normal and secure world
 */
void HardFault_Handler(void)
{
	uint32_t ahb_violation_status;
	uint32_t i;
	ahb_secure_fault_info_t ahb_violation_info;

	/* Handling SAU related secure faults */
	ERROR("\nEntering HardFault interrupt from S2!!!\n");
	if (SAU->SFSR != 0) {
		if (SAU->SFSR & SAU_SFSR_INVEP_Msk) {
			/* Invalid Secure state entry point */
			ERROR("SAU->SFSR:INVEP fault: Invalid entry point to secure world.\n");
		} else if (SAU->SFSR & SAU_SFSR_AUVIOL_Msk) {
			/* AUVIOL: SAU violation  */
			ERROR(
				"SAU->SFSR:AUVIOL fault: SAU violation. Access to secure memory from normal world.\n");
		} else if (SAU->SFSR & SAU_SFSR_INVTRAN_Msk) {
			/* INVTRAN: Invalid transition from secure to normal world  */
			ERROR("SAU->SFSR:INVTRAN fault: Invalid transition from secure to normal world.\n");
		} else {
			ERROR("Another SAU error.\n");
		}
		if (SAU->SFSR & SAU_SFSR_SFARVALID_Msk) {
			/* SFARVALID: SFAR contain valid address that caused secure violation */
			ERROR("Address that caused SAU violation is 0x%X.\n", SAU->SFAR);
		}
	}

	/* Handling secure bus related faults */
	if (SCB->CFSR != 0) {
		CFSR_Evaluate(SCB);
	}

	/* Handling non-secure bus related faults */
	if (SCB_NS->CFSR != 0) {
		CFSR_Evaluate(SCB_NS);
	}

	/* Handling AHB secure controller related faults.
	 * AHB secure controller faults raise secure bus fault. Detail fault info
	 * can be read from AHB secure controller violation registers */
	ahb_violation_status = AHB_SECURE_CTRL->SEC_VIO_INFO_VALID;
	if (ahb_violation_status != 0) {
		ERROR("\nAdditional AHB secure controller error information:\n");
		for (i = 0; i < AHB_LAYERS_COUNT; i++) {
			if (ahb_violation_status & 0x1U) {
				ahb_violation_info.value = AHB_SECURE_CTRL->SEC_VIO_MISC_INFO[i];
				ERROR("Secure error at AHB layer %d.\n", i);
				ERROR("Address that caused secure violation is 0x%X.\n",
					  AHB_SECURE_CTRL->SEC_VIO_ADDR[i]);
				ERROR("Secure error caused by bus master number %d.\n",
					  ahb_violation_info.fault_info.master_number);
				ERROR("Security level of master %d.\n",
					  ahb_violation_info.fault_info.master_sec_level);
				ERROR("Secure error happened during ");
				switch (ahb_violation_info.fault_info.access_type) {
				case 0:
					ERROR("read code access.\n");
					break;
				case 2:
					ERROR("read data access.\n");
					break;
				case 3:
					ERROR("read code access.\n");
					break;
				default:
					ERROR("unknown access.\n");
					break;
				}
			}
			ahb_violation_status = ahb_violation_status >> 1;
		}
	}

	for (;;)
		;
}

/**
 * Evaluate the Configurable Fault Status Register
 */
bool CFSR_Evaluate(SCB_Type *scb)
{
	bool exec_continue = false;
	if (scb->CFSR & SCB_CFSR_MEMFAULTSR_Msk) {
		ERROR("CFSR MemManage fault\n");

		exec_continue = MFSR_Evaluate(scb);
	}
	if (scb->CFSR & SCB_CFSR_USGFAULTSR_Msk) {
		ERROR("CFSR Usage Fault\n");

		UFSR_Evaluate(scb);
	}
	if (scb->CFSR & SCB_CFSR_BUSFAULTSR_Msk) {
		ERROR("CFSR Bus Fault\n");

		BFSR_Evaluate(scb);
	}
	return exec_continue;
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
