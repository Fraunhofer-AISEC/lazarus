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
#include "stdbool.h"
#include "LPC55S69_cm33_core0.h"
#include "lzport_debug_output/lzport_debug_output.h"
#include "lzport_memory/lzport_memory.h"

#define FLASH_START 0x10000000
#define FLASH_REGION_SIZE 0x8000 // 32 kB
#define FLASH_REGION_COUNT 20
#define ROM_START 0x03000000
#define ROM_REGION_SIZE 0x1000 // 4 kB
#define ROM_REGION_COUNT 32
#define RAM_REGION_SIZE 0x1000 // 4 kB
#define RAMX_START 0x04000000
#define RAMX_REGION_COUNT 8
#define RAM_START 0x20000000
#define RAM0_REGION_COUNT 16
#define RAM1_REGION_COUNT 16
#define RAM2_REGION_COUNT 16
#define RAM3_REGION_COUNT 16
#define RAM4_REGION_COUNT 4

static void configure_nsc_region(uint32_t region_nbr, uint32_t base_addr, uint32_t size);
static void configure_ns_region(uint32_t region_nbr, uint32_t base_addr, uint32_t size);
static void print_control(void);
static void print_flash_rom(void);
static void print_ram(void);
static void print_tier(uint32_t value);

void init_trustzone(void)
{
	/* Disable SAU */
	SAU->CTRL = 0U;

	/* Configure SAU region 0 - NS FLASH for CODE */
	configure_ns_region(0, LZ_FLASH_NS_START, LZ_FLASH_NS_SIZE);

	/* Configure SAU region 1 - NS RAM for non-secure apps */
	configure_ns_region(1, RAM_NS_START, RAM_NS_SIZE);

	/* Configure SAU region 2 - NS peripherals 1 */
	configure_ns_region(2, PERIPH_NS_START_1, PERIPH_NS_SIZE_1);

	/* Configure SAU region 3 - NS peripherals 2 */
	configure_ns_region(3, PERIPH_NS_START_2, PERIPH_NS_SIZE_2);

	/* Configure SAU region 5 - NSC FLASH for Lazarus Core */
	configure_nsc_region(4, LZ_CORE_NSC_START, LZ_CORE_NSC_SIZE);

	/* Force memory writes before continuing */
	__DSB();
	/* Flush and refill pipeline with updated permissions */
	__ISB();
	/* Enable SAU */
	SAU->CTRL = 1U;

	// Configure USART2 for ESP communication as non-secure
	NVIC_SetTargetState(FLEXCOMM2_IRQn);

	// Configure WWDT IRQ for AWDT as secure
	NVIC_ClearTargetState(WDT_BOD_IRQn);

	// Configure other IRQs as non-secure so that they can be used by the firmware
	// as required
	//--------------------------------------------------------------------
	//--- Interrupts: Interrupt security configuration -------------------
	//--------------------------------------------------------------------
	// Possible values for every interrupt:
	//  0b0    Secure
	//  0b1    Non-secure
	//--------------------------------------------------------------------
	// NVIC->ITNS[0] = 0;
	// NVIC->ITNS[1] = 0;
}

void init_secure_ahb_controller(void)
{
	dbgprint(DBG_INFO, "INFO: Initializing Secure AHB controller..\n");
	//--------------------------------------------------------------------
	//--- AHB Security Level Configurations ------------------------------
	//--------------------------------------------------------------------
	// Configuration of AHB Secure Controller
	// Possible values for every memory sector or peripheral rule:
	//  0    Non-secure, user access allowed
	//  1    Non-secure, privileged access allowed
	//  2    Secure, user access allowed
	//  3    Secure, privileged access allowed

	// Each configurable flash subregion has a size of 0x8000 (32kB)
	// name       	start     	end			subregions	security tier
	// lz_dicepp	0x00000000	0x0000FFFF	2			3
	// lz_core		0x00010000	0x00027FFF	3			2
	// lz_cpatcher	0x00028000  0x00037FFF  2			2
	// rest			0x00028000	0x9FFFFFFF	15			0
	// These regions are configured in the SEC_CTRL_FLASH_MEM_RULES 0-2
	AHB_SECURE_CTRL->SEC_CTRL_FLASH_ROM[0].SEC_CTRL_FLASH_MEM_RULE[0] = 0x02222233U;
	AHB_SECURE_CTRL->SEC_CTRL_FLASH_ROM[0].SEC_CTRL_FLASH_MEM_RULE[1] = 0x00000000U;
	AHB_SECURE_CTRL->SEC_CTRL_FLASH_ROM[0].SEC_CTRL_FLASH_MEM_RULE[2] = 0x00000000U;

	// The entire ROM which contains the Flash ROM API is only accessible by Lazarus
	AHB_SECURE_CTRL->SEC_CTRL_FLASH_ROM[0].SEC_CTRL_ROM_MEM_RULE[0] = 0x22222222U;
	AHB_SECURE_CTRL->SEC_CTRL_FLASH_ROM[0].SEC_CTRL_ROM_MEM_RULE[1] = 0x22222222U;
	AHB_SECURE_CTRL->SEC_CTRL_FLASH_ROM[0].SEC_CTRL_ROM_MEM_RULE[2] = 0x22222222U;
	AHB_SECURE_CTRL->SEC_CTRL_FLASH_ROM[0].SEC_CTRL_ROM_MEM_RULE[3] = 0x22222222U;

	// Each configurable RAM subregion has a size of 0x1000 (4kB)
	// Region		Start		End			Subregions	Security Tier
	// RAM X											0
	// Secure RAM	0x20000000	0x20007FFF	8			2 (For lz_core)
	// NS RAM 		0x20008000	0x2003FFFF	60			0
	AHB_SECURE_CTRL->SEC_CTRL_RAMX[0].MEM_RULE[0] = 0x00000000U;
	AHB_SECURE_CTRL->SEC_CTRL_RAM0[0].MEM_RULE[0] = 0x22222222U;
	AHB_SECURE_CTRL->SEC_CTRL_RAM0[0].MEM_RULE[1] = 0x00000000U;
	AHB_SECURE_CTRL->SEC_CTRL_RAM1[0].MEM_RULE[0] = 0x00000000U;
	AHB_SECURE_CTRL->SEC_CTRL_RAM1[0].MEM_RULE[1] = 0x00000000U;
	AHB_SECURE_CTRL->SEC_CTRL_RAM2[0].MEM_RULE[0] = 0x00000000U;
	AHB_SECURE_CTRL->SEC_CTRL_RAM2[0].MEM_RULE[1] = 0x00000000U;
	AHB_SECURE_CTRL->SEC_CTRL_RAM3[0].MEM_RULE[0] = 0x00000000U;
	AHB_SECURE_CTRL->SEC_CTRL_RAM3[0].MEM_RULE[1] = 0x00000000U;
	AHB_SECURE_CTRL->SEC_CTRL_RAM4[0].MEM_RULE[0] = 0x00000000U;
	AHB_SECURE_CTRL->SEC_CTRL_USB_HS[0].MEM_RULE[0] = 0x00000000U;

	//--- Security level configuration of peripherals --------------------
	// All peripherals are accessible for the application except those that are defined as
	// critical peripherals by Lazarus: WWDT, FMC, PMC
	AHB_SECURE_CTRL->SEC_CTRL_APB_BRIDGE[0].SEC_CTRL_APB_BRIDGE0_MEM_CTRL0 = 0x00000000U;
	// Watchdog: WWDT_RULE[17:16] is set to 0x2 (secure non-privileged)
	AHB_SECURE_CTRL->SEC_CTRL_APB_BRIDGE[0].SEC_CTRL_APB_BRIDGE0_MEM_CTRL1 = 0x00020000U;
	AHB_SECURE_CTRL->SEC_CTRL_APB_BRIDGE[0].SEC_CTRL_APB_BRIDGE0_MEM_CTRL2 = 0x00000000U;
	// Power Controller: PMC_RULE[1:0] is set to 0x2 (secure non-privileged)
	AHB_SECURE_CTRL->SEC_CTRL_APB_BRIDGE[0].SEC_CTRL_APB_BRIDGE1_MEM_CTRL0 = 0x00000002U;
	AHB_SECURE_CTRL->SEC_CTRL_APB_BRIDGE[0].SEC_CTRL_APB_BRIDGE1_MEM_CTRL1 = 0x00000000U;
	// Flash Controller: FLASH_CTRL_RULE[17:16] is set to 0x2 (secure non-privileged)
	AHB_SECURE_CTRL->SEC_CTRL_APB_BRIDGE[0].SEC_CTRL_APB_BRIDGE1_MEM_CTRL2 = 0x00020000U;
	AHB_SECURE_CTRL->SEC_CTRL_APB_BRIDGE[0].SEC_CTRL_APB_BRIDGE1_MEM_CTRL3 = 0x00000000U;
	AHB_SECURE_CTRL->SEC_CTRL_AHB0_0_SLAVE_RULE = 0x00000000U;
	AHB_SECURE_CTRL->SEC_CTRL_AHB0_1_SLAVE_RULE = 0;
	AHB_SECURE_CTRL->SEC_CTRL_AHB1_0_SLAVE_RULE = 0;
	AHB_SECURE_CTRL->SEC_CTRL_AHB1_1_SLAVE_RULE = 0;
	AHB_SECURE_CTRL->SEC_CTRL_AHB2[0].SEC_CTRL_AHB2_0_SLAVE_RULE = 0;
	AHB_SECURE_CTRL->SEC_CTRL_AHB2[0].SEC_CTRL_AHB2_1_SLAVE_RULE = 0;

	//--- Security level configuration of masters ------------------------
	// Other masters only have non-secure non-privileged access by now
	// can be changed to non-secure privileged if required
	AHB_SECURE_CTRL->MASTER_SEC_LEVEL = 0x00000000U;
	AHB_SECURE_CTRL->MASTER_SEC_ANTI_POL_REG = 0x3FFFFFFFU;

	//--------------------------------------------------------------------
	//--- Pins: Reading GPIO state ---------------------------------------
	//--------------------------------------------------------------------
	// Possible values for every pin:
	//  0b0    Deny
	//  0b1    Allow
	//--------------------------------------------------------------------
	AHB_SECURE_CTRL->SEC_GPIO_MASK0 = 0xFFFFFFFFU;
	AHB_SECURE_CTRL->SEC_GPIO_MASK1 = 0xFFFFFFFFU;

	//--------------------------------------------------------------------
	//--- Interrupts: Interrupt handling by Core1 ------------------------
	//--------------------------------------------------------------------
	// Possible values for every interrupt:
	//  0b0    Deny
	//  0b1    Allow
	//--------------------------------------------------------------------
	// WDT IRQ secure
	AHB_SECURE_CTRL->SEC_CPU_INT_MASK0 = 0xFFFFFFFFU;
	AHB_SECURE_CTRL->SEC_CPU_INT_MASK1 = 0xFFFFFFFFU;

	//--------------------------------------------------------------------
	//--- Global Options -------------------------------------------------
	//--------------------------------------------------------------------

	// Core Registers
	// [13] BFHFNMINS = 0x1 -> hardfault, NMI fault and bus fault are non-secure
	SCB->AIRCR = (SCB->AIRCR & 0x000009FF7U) | 0x005FA2000U;
	SCB->SCR &= 0x00000001CU;
	// TODO Check if secure fault should be enabled (currently, it escalates to a hardfault)
	// Set Bit 19 to enable the secure fault if implemented
	SCB->SHCSR &= 0x0FFF7FFFFU;
	// Enable non-secure access to the floating point extension, MVE and co-processors 0 and 1
	SCB->NSACR = 0x00000C03U;
	// Coprocessor Power Control Register
	SCnSCB->CPPWR = 0x00000000;

	// Secure GPIO MASK and CPU1 MASK registers are writtable
	AHB_SECURE_CTRL->SEC_MASK_LOCK = 0x00000A0AU;

	// Lock SAU and the CPU0 Lock Register itself
	AHB_SECURE_CTRL->CM33_LOCK_REG = 0x000001AAU;
	// CPU1 has only access to NS VTOR and NS MPU
	AHB_SECURE_CTRL->MCM33_LOCK_REG = 0x0000000AU;

	// Configure Secure AHB Controller Miscellaneous Control Register
	// Field					Value		Meaning
	// WRITE_LOCK				0x2			DISABLED, will be enabled through DP register
	// ENABLE_SECURE_CHECKING	0x1			AHB bus matrix secure checking ENABLED
	// ENABLE_S_PRIV_CHECK		0x1			AHB bus matrix secure privilege check ENABLED
	// ENABLE_NS_PRIV_CHECK		0x2			AHB bus matrix non-secure privilege check DISABLED
	// DIABLE_VIOLATION_ABORT	0x2			Do not cause abort on violations
	// DISABLE SI-MASTER STRICT	0x1			Tier mode, simple master can access same or lower tier
	// DISABLE SM-MASTER STRICT	0x1			Tier mode, smart master can access same or lower tier
	// IDAU_ALL_NS				0x2			IDAU is enabled
	AHB_SECURE_CTRL->MISC_CTRL_REG =
		AHB_SECURE_CTRL_MISC_CTRL_REG_WRITE_LOCK(0x2) |
		AHB_SECURE_CTRL_MISC_CTRL_REG_ENABLE_SECURE_CHECKING(0x1U) |
		AHB_SECURE_CTRL_MISC_CTRL_REG_ENABLE_S_PRIV_CHECK(0x1) |
		AHB_SECURE_CTRL_MISC_CTRL_DP_REG_ENABLE_NS_PRIV_CHECK(0x2) |
		AHB_SECURE_CTRL_MISC_CTRL_REG_DISABLE_VIOLATION_ABORT(0x2) |
		AHB_SECURE_CTRL_MISC_CTRL_REG_DISABLE_SIMPLE_MASTER_STRICT_MODE(0x1) |
		AHB_SECURE_CTRL_MISC_CTRL_REG_DISABLE_SMART_MASTER_STRICT_MODE(0x1) |
		AHB_SECURE_CTRL_MISC_CTRL_REG_IDAU_ALL_NS(0x2);

	// Configure MISC DP register with the same configuration, otherwise the related control signals
	// are set to the restrictive mode (datasheet p982). Only set the WRITE_LOCK to a different
	// value, which means the control registers are now locked and cannot be written anymore
	AHB_SECURE_CTRL->MISC_CTRL_DP_REG =
		(AHB_SECURE_CTRL->MISC_CTRL_REG & ~AHB_SECURE_CTRL_MISC_CTRL_REG_WRITE_LOCK_MASK) |
		AHB_SECURE_CTRL_MISC_CTRL_REG_WRITE_LOCK(0x1);

	dbgprint(DBG_VERB, "INFO: MISC_CTRL_REG:    %X\n", AHB_SECURE_CTRL->MISC_CTRL_REG);
	dbgprint(DBG_VERB, "INFO: MISC_CTRL_DP_REG: %X\n", AHB_SECURE_CTRL->MISC_CTRL_DP_REG);
}

void print_secure_ahb_controller_status(void)
{
	dbgprint(DBG_SAHBC, "--- SECURE AHB CONTROLLER STATUS ---\n");
	print_control();
	print_flash_rom();
	print_ram();
}

// ============================== Private function definitions =====================================

void configure_nsc_region(uint32_t region_nbr, uint32_t base_addr, uint32_t size)
{
	/* Set SAU region number */
	SAU->RNR = region_nbr;
	/* Region base address */
	SAU->RBAR = (base_addr & SAU_RBAR_BADDR_Msk);
	/* Region end address */
	SAU->RLAR = ((base_addr + size - 1) & SAU_RLAR_LADDR_Msk) |
				/* Region memory attribute index */
				((1u << SAU_RLAR_NSC_Pos) & SAU_RLAR_NSC_Msk) |
				/* Enable region */
				((1u << SAU_RLAR_ENABLE_Pos) & SAU_RLAR_ENABLE_Msk);

	dbgprint(DBG_VERB, "INFO: Region %u from 0x%x to 0x%x as %s. State = %s\n", SAU->RNR, SAU->RBAR,
			 SAU->RLAR, ((SAU->RLAR & (1U << SAU_RLAR_NSC_Pos)) ? "NSC" : "NS"),
			 ((SAU->RLAR & (1U << SAU_RLAR_ENABLE_Pos)) ? "ENABLED" : "DISABLED"));
}

void configure_ns_region(uint32_t region_nbr, uint32_t base_addr, uint32_t size)
{
	/* Set SAU region number */
	SAU->RNR = region_nbr;
	/* Region base address */
	SAU->RBAR = (base_addr & SAU_RBAR_BADDR_Msk);
	/* Region end address */
	SAU->RLAR = ((base_addr + size - 1) & SAU_RLAR_LADDR_Msk) |
				/* Region memory attribute index */
				((0u << SAU_RLAR_NSC_Pos) & SAU_RLAR_NSC_Msk) |
				/* Enable region */
				((1u << SAU_RLAR_ENABLE_Pos) & SAU_RLAR_ENABLE_Msk);

	dbgprint(DBG_VERB, "INFO: Region %u from 0x%x to 0x%x as %s. State = %s\n", SAU->RNR, SAU->RBAR,
			 (SAU->RLAR & SAU_RLAR_LADDR_Msk),
			 ((SAU->RLAR & (1U << SAU_RLAR_NSC_Pos)) ? "NSC" : "NS"),
			 ((SAU->RLAR & (1U << SAU_RLAR_ENABLE_Pos)) ? "ENABLED" : "DISABLED"));
}

void print_control(void)
{
	dbgprint(DBG_SAHBC, "\n");
	dbgprint(DBG_SAHBC, "MISC_CTRL_REG: \n");

	uint32_t v = AHB_SECURE_CTRL->MISC_CTRL_REG & 0x3;
	dbgprint(DBG_SAHBC, "WRITE_LOCK                      = %d: %s\n", v,
			 (v == 0x2) ? "UNLOCKED" : "LOCKED");
	v = AHB_SECURE_CTRL->MISC_CTRL_DP_REG & 0x3;
	dbgprint(DBG_SAHBC, "WRITE_LOCK_DP                   = %d: %s\n", v,
			 (v == 0x2) ? "UNLOCKED" : "LOCKED");

	v = (AHB_SECURE_CTRL->MISC_CTRL_REG >> 2) & 0x3;
	dbgprint(DBG_SAHBC, "ENABLE_SECURE_CHECKING          = %d: %s\n", v,
			 (v == 0x2) ? "DISABLED" : "ENABLED");
	v = (AHB_SECURE_CTRL->MISC_CTRL_DP_REG >> 2) & 0x3;
	dbgprint(DBG_SAHBC, "ENABLE_SECURE_CHECKING_DP       = %d: %s\n", v,
			 (v == 0x2) ? "DISABLED" : "ENABLED");

	v = (AHB_SECURE_CTRL->MISC_CTRL_REG >> 4) & 0x3;
	dbgprint(DBG_SAHBC, "ENABLE_S_PRIV_CHECK             = %d: %s\n", v,
			 (v == 0x2) ? "DISABLED" : "ENABLED");
	v = (AHB_SECURE_CTRL->MISC_CTRL_DP_REG >> 4) & 0x3;
	dbgprint(DBG_SAHBC, "ENABLE_S_PRIV_CHECK_DP          = %d: %s\n", v,
			 (v == 0x2) ? "DISABLED" : "ENABLED");

	v = (AHB_SECURE_CTRL->MISC_CTRL_REG >> 6) & 0x3;
	dbgprint(DBG_SAHBC, "ENABLE_NS_PRIV_CHECK            = %d: %s\n", v,
			 (v == 0x2) ? "DISABLED" : "ENABLED");
	v = (AHB_SECURE_CTRL->MISC_CTRL_DP_REG >> 6) & 0x3;
	dbgprint(DBG_SAHBC, "ENABLE_NS_PRIV_CHECK_DP         = %d: %s\n", v,
			 (v == 0x2) ? "DISABLED" : "ENABLED");

	v = (AHB_SECURE_CTRL->MISC_CTRL_REG >> 8) & 0x3;
	dbgprint(DBG_SAHBC, "DISABLE_VIOLATION_ABORT         = %d: %s\n", v,
			 (v == 0x2) ? "ABORT" : "IRQ");
	v = (AHB_SECURE_CTRL->MISC_CTRL_DP_REG >> 8) & 0x3;
	dbgprint(DBG_SAHBC, "DISABLE_VIOLATION_ABORT_DP      = %d: %s\n", v,
			 (v == 0x2) ? "ABORT" : "IRQ");

	v = (AHB_SECURE_CTRL->MISC_CTRL_REG >> 10) & 0x3;
	dbgprint(DBG_SAHBC, "DISABLE_SIMPLE_MASTER_STRCT_MODE= %d: %s\n", v,
			 (v == 0x2) ? "STRICT" : "RELAXED");
	v = (AHB_SECURE_CTRL->MISC_CTRL_DP_REG >> 10) & 0x3;
	dbgprint(DBG_SAHBC, "DISABLE_SMPL_MSTER_STRCT_MODE_DP= %d: %s\n", v,
			 (v == 0x2) ? "STRICT" : "RELAXED");

	v = (AHB_SECURE_CTRL->MISC_CTRL_REG >> 12) & 0x3;
	dbgprint(DBG_SAHBC, "DISABLE_SMART_MASTER_STRICT_MODE= %d: %s\n", v,
			 (v == 0x2) ? "STRICT" : "RELAXED");
	v = (AHB_SECURE_CTRL->MISC_CTRL_DP_REG >> 12) & 0x3;
	dbgprint(DBG_SAHBC, "DISABLE_SMRT_MSTER_STRCT_MODE_DP= %d: %s\n", v,
			 (v == 0x2) ? "STRICT" : "RELAXED");

	v = (AHB_SECURE_CTRL->MISC_CTRL_REG >> 14) & 0x3;
	dbgprint(DBG_SAHBC, "IDAU_ALL_NS                     = %d: %s\n", v,
			 (v == 0x2) ? "IDAU ON" : "IDAU OFF");
	v = (AHB_SECURE_CTRL->MISC_CTRL_DP_REG >> 14) & 0x3;
	dbgprint(DBG_SAHBC, "IDAU_ALL_NS_DP                  = %d: %s\n", v,
			 (v == 0x2) ? "IDAU ON" : "IDAU OFF");
}

void print_ram(void)
{
	dbgprint(DBG_SAHBC, "\n");
	dbgprint(DBG_SAHBC, "RAMX ACCESS RULES\n");
	dbgprint(DBG_SAHBC, "RAMX Slave Rule: ");
	print_tier(AHB_SECURE_CTRL->SEC_CTRL_RAMX[0].SLAVE_RULE & 0x3);
	uint32_t curr_location = RAMX_START;
	dbgprint(DBG_SAHBC, "Sub-Region Rules:\n");
	for (uint8_t i = 0; i < RAMX_REGION_COUNT; i++) {
		uint32_t value = (AHB_SECURE_CTRL->SEC_CTRL_RAMX[0].MEM_RULE[0] >> (i * 4)) & 0x3;
		if (value) {
			dbgprint(DBG_SAHBC, "Region %02d (%08x-%08x): ", i, curr_location,
					 curr_location + RAM_REGION_SIZE - 1);
			print_tier(value);
			curr_location += RAM_REGION_SIZE;
		}
	}
	dbgprint(DBG_SAHBC, "\n");
	dbgprint(DBG_SAHBC, "RAM ACCESS RULES\n");
	dbgprint(DBG_SAHBC, "RAM0 Slave Rule: ");
	print_tier(AHB_SECURE_CTRL->SEC_CTRL_RAM0[0].SLAVE_RULE & 0x3);
	dbgprint(DBG_SAHBC, "Sub-Region Rules:\n");
	curr_location = RAM_START;
	for (uint8_t i = 0; i < RAM0_REGION_COUNT; i++) {
		uint32_t value = (AHB_SECURE_CTRL->SEC_CTRL_RAM0[0].MEM_RULE[0] >> (i * 4)) & 0x3;
		if (value) {
			dbgprint(DBG_SAHBC, "Region %02d (%08x-%08x): ", i, curr_location,
					 curr_location + RAM_REGION_SIZE - 1);
			print_tier(value);
			curr_location += RAM_REGION_SIZE;
		}
	}
	dbgprint(DBG_SAHBC, "\n");
	dbgprint(DBG_SAHBC, "RAM1 Slave Rule: ");
	print_tier(AHB_SECURE_CTRL->SEC_CTRL_RAM1[0].SLAVE_RULE & 0x3);
	dbgprint(DBG_SAHBC, "Sub-Region Rules:\n");
	for (uint8_t i = 0; i < RAM1_REGION_COUNT; i++) {
		uint32_t value = (AHB_SECURE_CTRL->SEC_CTRL_RAM1[0].MEM_RULE[0] >> (i * 4)) & 0x3;
		if (value) {
			dbgprint(DBG_SAHBC, "Region %02d (%08x-%08x): ", i, curr_location,
					 curr_location + RAM_REGION_SIZE - 1);
			print_tier(value);
			curr_location += RAM_REGION_SIZE;
		}
	}
	dbgprint(DBG_SAHBC, "\n");
	dbgprint(DBG_SAHBC, "RAM2 Slave Rule: ");
	print_tier(AHB_SECURE_CTRL->SEC_CTRL_RAM2[0].SLAVE_RULE & 0x3);
	dbgprint(DBG_SAHBC, "Sub-Region Rules:\n");
	for (uint8_t i = 0; i < RAM2_REGION_COUNT; i++) {
		uint32_t value = (AHB_SECURE_CTRL->SEC_CTRL_RAM2[0].MEM_RULE[0] >> (i * 4)) & 0x3;
		if (value) {
			dbgprint(DBG_SAHBC, "Region %02d (%08x-%08x): ", i, curr_location,
					 curr_location + RAM_REGION_SIZE - 1);
			print_tier(value);
			curr_location += RAM_REGION_SIZE;
		}
	}
	dbgprint(DBG_SAHBC, "\n");
	dbgprint(DBG_SAHBC, "RAM3 Slave Rule: ");
	print_tier(AHB_SECURE_CTRL->SEC_CTRL_RAM3[0].SLAVE_RULE & 0x3);
	dbgprint(DBG_SAHBC, "Sub-Region Rules:\n");
	for (uint8_t i = 0; i < RAM3_REGION_COUNT; i++) {
		uint32_t value = (AHB_SECURE_CTRL->SEC_CTRL_RAM3[0].MEM_RULE[0] >> (i * 4)) & 0x3;
		if (value) {
			dbgprint(DBG_SAHBC, "Region %02d (%08x-%08x): ", i, curr_location,
					 curr_location + RAM_REGION_SIZE - 1);
			print_tier(value);
			curr_location += RAM_REGION_SIZE;
		}
	}
	dbgprint(DBG_SAHBC, "\n");
	dbgprint(DBG_SAHBC, "RAM4 Slave Rule: ");
	print_tier(AHB_SECURE_CTRL->SEC_CTRL_RAM4[0].SLAVE_RULE & 0x3);
	dbgprint(DBG_SAHBC, "Sub-Region Rules:\n");
	for (uint8_t i = 0; i < RAM4_REGION_COUNT; i++) {
		uint32_t value = (AHB_SECURE_CTRL->SEC_CTRL_RAM4[0].MEM_RULE[0] >> (i * 4)) & 0x3;
		if (value) {
			dbgprint(DBG_SAHBC, "Region %02d (%08x-%08x): ", i, curr_location,
					 curr_location + RAM_REGION_SIZE - 1);
			print_tier(value);
			curr_location += RAM_REGION_SIZE;
		}
	}
}

void print_flash_rom(void)
{
	dbgprint(DBG_SAHBC, "FLASH ACCESS RULES\n");
	dbgprint(DBG_SAHBC, "Flash Slave Rule: ");
	print_tier(AHB_SECURE_CTRL->SEC_CTRL_FLASH_ROM[0].SLAVE_RULE & 0x3);
	uint32_t curr_location = FLASH_START;
	dbgprint(DBG_SAHBC, "Sub-Region Rules:\n");
	for (uint8_t i = 0; i < FLASH_REGION_COUNT; i++) {
		uint32_t value = (AHB_SECURE_CTRL->SEC_CTRL_FLASH_ROM[0].SEC_CTRL_FLASH_MEM_RULE[i / 8] >>
						  ((i % 8) * 4)) &
						 0x3;
		// Print only if value is not zero (non-secure unprivileged = default)
		if (value) {
			dbgprint(DBG_SAHBC, "Region %02d (%08x-%08x): ", i, curr_location,
					 curr_location + FLASH_REGION_SIZE - 1);
			print_tier(value);
		}
		curr_location += FLASH_REGION_SIZE;
	}
	dbgprint(DBG_SAHBC, "\n");
	dbgprint(DBG_SAHBC, "ROM ACCESS RULES\n");
	dbgprint(DBG_SAHBC, "ROM Slave Rule: ");
	print_tier((AHB_SECURE_CTRL->SEC_CTRL_FLASH_ROM[0].SLAVE_RULE >> 4) & 0x3);
	curr_location = ROM_START;
	dbgprint(DBG_SAHBC, "Sub-Region Rules:\n");
	for (uint8_t i = 0; i < ROM_REGION_COUNT; i++) {
		uint32_t value =
			(AHB_SECURE_CTRL->SEC_CTRL_FLASH_ROM[0].SEC_CTRL_ROM_MEM_RULE[i / 8] >> ((i % 8) * 4)) &
			0x3;
		if (value) {
			dbgprint(DBG_SAHBC, "Region %02d (%08x-%08x): ", i, curr_location,
					 curr_location + ROM_REGION_SIZE - 1);
			print_tier(value);
		}
		curr_location += ROM_REGION_SIZE;
	}
}

void print_tier(uint32_t value)
{
	switch (value) {
	case 0:
		dbgprint(DBG_SAHBC, "%d = non-secure, unprivileged\n", value);
		break;
	case 1:
		dbgprint(DBG_SAHBC, "%d = non-secure, privileged\n", value);
		break;
	case 2:
		dbgprint(DBG_SAHBC, "%d = secure,     unprivileged\n", value);
		break;
	case 3:
		dbgprint(DBG_SAHBC, "%d = secure,     privileged\n", value);
		break;
	}
	return;
}
