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

#include "LPC55S69_cm33_core0.h"
#include "fsl_common.h"
#include "fsl_spi.h"
#include "fsl_reset.h"
#include "bme280.h"

#define EXAMPLE_SPI_MASTER SPI8
#define EXAMPLE_SPI_MASTER_CLK_SRC kCLOCK_HsLspi
#define EXAMPLE_SPI_MASTER_CLK_FREQ                                                                \
	12000000U // TODO uses PMC which is secure: CLOCK_GetFreq(kCLOCK_HsLspi)
#define EXAMPLE_SPI_SSEL 1
#define EXAMPLE_SPI_SPOL kSPI_SpolActiveAllLow

void lzport_spi_init(void)
{
	spi_master_config_t userConfig = { 0 };
	uint32_t srcFreq = 0;

	/* attach 12 MHz clock to SPI3 */
	CLOCK_AttachClk(kFRO12M_to_HSLSPI);

	/* reset FLEXCOMM for SPI */
	RESET_PeripheralReset(kHSLSPI_RST_SHIFT_RSTn);

	SPI_MasterGetDefaultConfig(&userConfig);
	srcFreq = EXAMPLE_SPI_MASTER_CLK_FREQ;
	userConfig.sselNum = (spi_ssel_t)EXAMPLE_SPI_SSEL;
	userConfig.sselPol = (spi_spol_t)EXAMPLE_SPI_SPOL;
	SPI_MasterInit(EXAMPLE_SPI_MASTER, &userConfig, srcFreq);
}

int8_t lzport_spi_read(uint8_t reg_addr, uint8_t *reg_data, uint32_t len, void *intf_ptr)
{
	int8_t ret = 0; /* Return 0 for Success, non-zero for failure */

	/*
	 * Data on the bus should be like
	 * |----------------+---------------------+-------------|
	 * | MOSI           | MISO                | Chip Select |
	 * |----------------+---------------------|-------------|
	 * | (don't care)   | (don't care)        | HIGH        |
	 * | (reg_addr)     | (don't care)        | LOW         |
	 * | (don't care)   | (reg_data[0])       | LOW         |
	 * | (....)         | (....)              | LOW         |
	 * | (don't care)   | (reg_data[len - 1]) | LOW         |
	 * | (don't care)   | (don't care)        | HIGH        |
	 * |----------------+---------------------|-------------|
	 */
	spi_transfer_t spi_transfer = { 0x0 };
	uint8_t tx_data[len + 1];
	uint8_t rx_data[len + 1];
	memset(tx_data, 0x0, sizeof(tx_data));
	tx_data[0] = reg_addr;

	spi_transfer.txData = tx_data;
	spi_transfer.rxData = rx_data;
	spi_transfer.dataSize = sizeof(tx_data);
	spi_transfer.configFlags = kSPI_FrameAssert;
	if (SPI_MasterTransferBlocking(EXAMPLE_SPI_MASTER, &spi_transfer) != kStatus_Success) {
		ret = INT8_C(-1);
	} else {
		memcpy(reg_data, rx_data + 1, len);
		ret = BME280_OK;
	}

	return ret;
}

int8_t lzport_spi_write(uint8_t reg_addr, const uint8_t *reg_data, uint32_t len, void *intf_ptr)
{
	int8_t ret = 0; /* Return 0 for Success, non-zero for failure */

	/*
	 * Data on the bus should be like
	 * |---------------------+--------------+-------------|
	 * | MOSI                | MISO         | Chip Select |
	 * |---------------------+--------------|-------------|
	 * | (don't care)        | (don't care) | HIGH        |
	 * | (reg_addr)          | (don't care) | LOW         |
	 * | (reg_data[0])       | (don't care) | LOW         |
	 * | (....)              | (....)       | LOW         |
	 * | (reg_data[len - 1]) | (don't care) | LOW         |
	 * | (don't care)        | (don't care) | HIGH        |
	 * |---------------------+--------------|-------------|
	 */
	spi_transfer_t spi_transfer = { 0x0 };
	uint8_t tx_data[len + 1];
	uint8_t rx_data[len + 1];
	tx_data[0] = reg_addr;
	memcpy((void *)(tx_data + 1), reg_data, len);

	spi_transfer.txData = tx_data;
	spi_transfer.rxData = rx_data;
	spi_transfer.dataSize = sizeof(tx_data);
	spi_transfer.configFlags = kSPI_FrameAssert;
	if (SPI_MasterTransferBlocking(EXAMPLE_SPI_MASTER, &spi_transfer) != kStatus_Success) {
		ret = INT8_C(-1);
	} else {
		ret = BME280_OK;
	}

	return ret;
}