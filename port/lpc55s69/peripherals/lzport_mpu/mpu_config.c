// Copyright(c) 2022 Fraunhofer AISEC

#include "stdint.h"
#include "stdbool.h"
#include "LPC55S69_cm33_core0.h"
#include "lzport_debug_output.h"
#include "lzport_memory.h"

#define MPU_REGION_DISABLE 0
#define MPU_REGION_ENABLE 1

#define MPU_MAIR_ATTR_DEVICE_VAL 0x04
#define MPU_MAIR_ATTR_DEVICE_IDX 0
#define MPU_MAIR_ATTR_CODE_VAL 0xAA
#define MPU_MAIR_ATTR_CODE_IDX 1
#define MPU_MAIR_ATTR_DATA_VAL 0xFF
#define MPU_MAIR_ATTR_DATA_IDX 2

#define MPU_XN_EXEC 0x0
#define MPU_XN_EXEC_NEVER 0x1

#define MPU_AP_RW_PRIV_ONLY 0x0
#define MPU_AP_RW_PRIV_UNPRIV 0x1
#define MPU_AP_RO_PRIV_ONLY 0x2
#define MPU_AP_RO_PRIV_UNPRIV 0x3

#define MPU_SHARED_NONE 0x0
#define MPU_SHARED_UNUSED 0x1
#define MPU_SHARED_OUTER 0x2
#define MPU_SHARED_INNER 0x3

#define SECURE_BIT_MASK 0x10000000

void init_s_mpu(void)
{
	// Check that device has MPU and number of regions
	uint8_t regions = (MPU->TYPE >> 8) & 0xFF;
	VERB("Number of MPU regions: %d\n", regions);

	// Disable MPU
	ARM_MPU_Disable();

	// TODO clear all regions necessary?
	for (size_t i = 0; i < regions; i++) {
		ARM_MPU_ClrRegion(i);
	}

	// Set MAIR attributes for 3 different types of memory
	// TODO taken from default memory map
	// Attr0: Peripheral, Device-nGnRE
	// Attr1: Code
	// Attr2: SRAM
	MPU->MAIR0 = (MPU_MAIR_ATTR_DEVICE_VAL << MPU_MAIR0_Attr0_Pos) |
				 (MPU_MAIR_ATTR_CODE_VAL << MPU_MAIR0_Attr1_Pos) |
				 (MPU_MAIR_ATTR_DATA_VAL << MPU_MAIR0_Attr2_Pos);

	// Configure MPU region 0 - DICEpp Data (accessible by privileged code only)
	MPU->RNR = 0;
	uint32_t start = LZ_DICEPP_CODE_START;
	uint32_t limit = LZ_DICEPP_DATA_START + LZ_DICEPP_DATA_SIZE;
	VERB("Configuring privileged r/w region from %x to %x\n", start, limit);

	MPU->RBAR = ((MPU_XN_EXEC << MPU_RBAR_XN_Pos) & MPU_RBAR_XN_Msk) |
				((MPU_AP_RW_PRIV_ONLY << MPU_RBAR_AP_Pos) & MPU_RBAR_AP_Msk) |
				((MPU_SHARED_NONE << MPU_RBAR_SH_Pos) & MPU_RBAR_SH_Msk) |
				(start & MPU_RBAR_BASE_Msk);

	MPU->RLAR = ((MPU_REGION_ENABLE << MPU_RLAR_EN_Pos) & MPU_RLAR_EN_Msk) |
				((MPU_MAIR_ATTR_CODE_IDX << MPU_RLAR_AttrIndx_Pos) & MPU_RLAR_AttrIndx_Msk) |
				((limit - 1) & MPU_RLAR_LIMIT_Msk);

	INFO("RBAR: %x, RLAR: %x\n", MPU->RBAR, MPU->RLAR);

	// Configure Lazarus Core and Non-Secure binaries and Flash (non-privileged)
	MPU->RNR = 1;
	start = LZ_CORE_HEADER_START;
	limit = 0x10000000 + LZ_STAGING_AREA_END + 4;
	VERB("Configuring non-privileged r/w region from %x to %x\n", start, limit);

	MPU->RBAR = ((MPU_XN_EXEC << MPU_RBAR_XN_Pos) & MPU_RBAR_XN_Msk) |
				((MPU_AP_RW_PRIV_UNPRIV << MPU_RBAR_AP_Pos) & MPU_RBAR_AP_Msk) |
				((MPU_SHARED_NONE << MPU_RBAR_SH_Pos) & MPU_RBAR_SH_Msk) |
				(start & MPU_RBAR_BASE_Msk);

	MPU->RLAR = ((MPU_REGION_ENABLE << MPU_RLAR_EN_Pos) & MPU_RLAR_EN_Msk) |
				((MPU_MAIR_ATTR_CODE_IDX << MPU_RLAR_AttrIndx_Pos) & MPU_RLAR_AttrIndx_Msk) |
				((limit - 1) & MPU_RLAR_LIMIT_Msk);

	INFO("RBAR: %x, RLAR: %x\n", MPU->RBAR, MPU->RLAR);

	MPU->RNR = 2;
	start = LZ_CORE_HEADER_START & ~SECURE_BIT_MASK;
	limit = (LZ_STAGING_AREA_END + 4);
	VERB("Configuring non-privileged r/w region from %x to %x\n", start, limit);

	MPU->RBAR = ((MPU_XN_EXEC << MPU_RBAR_XN_Pos) & MPU_RBAR_XN_Msk) |
				((MPU_AP_RW_PRIV_UNPRIV << MPU_RBAR_AP_Pos) & MPU_RBAR_AP_Msk) |
				((MPU_SHARED_NONE << MPU_RBAR_SH_Pos) & MPU_RBAR_SH_Msk) |
				(start & MPU_RBAR_BASE_Msk);

	MPU->RLAR = ((MPU_REGION_ENABLE << MPU_RLAR_EN_Pos) & MPU_RLAR_EN_Msk) |
				((MPU_MAIR_ATTR_CODE_IDX << MPU_RLAR_AttrIndx_Pos) & MPU_RLAR_AttrIndx_Msk) |
				((limit - 1) & MPU_RLAR_LIMIT_Msk);

	INFO("RBAR: %x, RLAR: %x\n", MPU->RBAR, MPU->RLAR);

	// Configure RAM
	MPU->RNR = 3;
	start = 0x30000000;
	limit = 0x30040000;
	VERB("Configuring non-privileged r/w region from %x to %x\n", start, limit);

	MPU->RBAR = ((MPU_XN_EXEC_NEVER << MPU_RBAR_XN_Pos) & MPU_RBAR_XN_Msk) |
				((MPU_AP_RW_PRIV_UNPRIV << MPU_RBAR_AP_Pos) & MPU_RBAR_AP_Msk) |
				((MPU_SHARED_NONE << MPU_RBAR_SH_Pos) & MPU_RBAR_SH_Msk) |
				(start & MPU_RBAR_BASE_Msk);

	MPU->RLAR = ((MPU_REGION_ENABLE << MPU_RLAR_EN_Pos) & MPU_RLAR_EN_Msk) |
				((MPU_MAIR_ATTR_DATA_IDX << MPU_RLAR_AttrIndx_Pos) & MPU_RLAR_AttrIndx_Msk) |
				((limit - 1) & MPU_RLAR_LIMIT_Msk);
	INFO("RBAR: %x, RLAR: %x\n", MPU->RBAR, MPU->RLAR);

	// TODO Check again if its really required to configure non-secure and secure address
	MPU->RNR = 4;
	start = 0x20000000;
	limit = 0x20040000;
	VERB("Configuring non-privileged r/w region from %x to %x\n", start, limit);

	MPU->RBAR = ((MPU_XN_EXEC_NEVER << MPU_RBAR_XN_Pos) & MPU_RBAR_XN_Msk) |
				((MPU_AP_RW_PRIV_UNPRIV << MPU_RBAR_AP_Pos) & MPU_RBAR_AP_Msk) |
				((MPU_SHARED_NONE << MPU_RBAR_SH_Pos) & MPU_RBAR_SH_Msk) |
				(start & MPU_RBAR_BASE_Msk);

	MPU->RLAR = ((MPU_REGION_ENABLE << MPU_RLAR_EN_Pos) & MPU_RLAR_EN_Msk) |
				((MPU_MAIR_ATTR_DATA_IDX << MPU_RLAR_AttrIndx_Pos) & MPU_RLAR_AttrIndx_Msk) |
				((limit - 1) & MPU_RLAR_LIMIT_Msk);

	INFO("RBAR: %x, RLAR: %x\n", MPU->RBAR, MPU->RLAR);

	// Configure Peripherals
	MPU->RNR = 5;
	start = 0x50000000;
	limit = 0xF0000000;
	VERB("Configuring non-privileged r/w region from %x to %x\n", start, limit);

	MPU->RBAR = ((MPU_XN_EXEC << MPU_RBAR_XN_Pos) & MPU_RBAR_XN_Msk) |
				((MPU_AP_RW_PRIV_UNPRIV << MPU_RBAR_AP_Pos) & MPU_RBAR_AP_Msk) |
				((MPU_SHARED_NONE << MPU_RBAR_SH_Pos) & MPU_RBAR_SH_Msk) |
				(start & MPU_RBAR_BASE_Msk);

	MPU->RLAR = ((MPU_REGION_ENABLE << MPU_RLAR_EN_Pos) & MPU_RLAR_EN_Msk) |
				((MPU_MAIR_ATTR_DEVICE_IDX << MPU_RLAR_AttrIndx_Pos) & MPU_RLAR_AttrIndx_Msk) |
				((limit - 1) & MPU_RLAR_LIMIT_Msk);

	INFO("RBAR: %x, RLAR: %x\n", MPU->RBAR, MPU->RLAR);

	// Configure ROM API, CASPER
	MPU->RNR = 6;
	start = 0x13000000;
	limit = 0x14010000;
	VERB("Configuring non-privileged r/w region from %x to %x\n", start, limit);

	MPU->RBAR = ((MPU_XN_EXEC << MPU_RBAR_XN_Pos) & MPU_RBAR_XN_Msk) |
				((MPU_AP_RW_PRIV_UNPRIV << MPU_RBAR_AP_Pos) & MPU_RBAR_AP_Msk) |
				((MPU_SHARED_NONE << MPU_RBAR_SH_Pos) & MPU_RBAR_SH_Msk) |
				(start & MPU_RBAR_BASE_Msk);

	MPU->RLAR = ((MPU_REGION_ENABLE << MPU_RLAR_EN_Pos) & MPU_RLAR_EN_Msk) |
				((MPU_MAIR_ATTR_CODE_IDX << MPU_RLAR_AttrIndx_Pos) & MPU_RLAR_AttrIndx_Msk) |
				((limit - 1) & MPU_RLAR_LIMIT_Msk);
	INFO("RBAR: %x, RLAR: %x\n", MPU->RBAR, MPU->RLAR);

	// ROM API, CASPER
	MPU->RNR = 7;
	start = 0x03000000;
	limit = 0x04010000;
	VERB("Configuring non-privileged r/w region from %x to %x\n", start, limit);

	MPU->RBAR = ((MPU_XN_EXEC_NEVER << MPU_RBAR_XN_Pos) & MPU_RBAR_XN_Msk) |
				((MPU_AP_RW_PRIV_UNPRIV << MPU_RBAR_AP_Pos) & MPU_RBAR_AP_Msk) |
				((MPU_SHARED_NONE << MPU_RBAR_SH_Pos) & MPU_RBAR_SH_Msk) |
				(start & MPU_RBAR_BASE_Msk);

	MPU->RLAR = ((MPU_REGION_ENABLE << MPU_RLAR_EN_Pos) & MPU_RLAR_EN_Msk) |
				((MPU_MAIR_ATTR_CODE_IDX << MPU_RLAR_AttrIndx_Pos) & MPU_RLAR_AttrIndx_Msk) |
				((limit - 1) & MPU_RLAR_LIMIT_Msk);

	INFO("RBAR: %x, RLAR: %x\n", MPU->RBAR, MPU->RLAR);

	// Enable MPU
	// PRIVDEFENA = 1: system address map as a memory region for privileged accesses enabled
	// HFNMIENA = 0: MPU is disabled for hardfault and NMI handler
	uint32_t mpu_ctrl = ((0x1 << MPU_CTRL_PRIVDEFENA_Pos) & MPU_CTRL_PRIVDEFENA_Msk) |
						((0x0 << MPU_CTRL_HFNMIENA_Pos) & MPU_CTRL_HFNMIENA_Msk);

	ARM_MPU_Enable(mpu_ctrl);
}