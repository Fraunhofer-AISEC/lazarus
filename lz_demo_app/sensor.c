// Copyright(c) 2022 Fraunhofer AISEC

#include "stdint.h"
#include "stdbool.h"
#include "stdio.h"
#include "fsl_common.h"
#include "fsl_spi.h"
#include "FreeRTOS.h"
#include "task.h"

#include "lz_config.h"
#include "lzport_gpio.h"
#include "lzport_debug_output.h"
#include "lzport_memory.h"
#include "lzport_rng.h"
#include "lz_common.h"
#include "lz_flash_handler.h"
#include "lz_awdt.h"

#include "net.h"
#include "bme280.h"
#include "sensor.h"
#include "user_input.h"

#define SENSOR_TASK_RANDOM 1

#define SENSOR_TASK_WAIT_MS 2000

#define EXAMPLE_SPI_MASTER SPI8
#define EXAMPLE_SPI_MASTER_CLK_SRC kCLOCK_HsLspi
#define EXAMPLE_SPI_MASTER_CLK_FREQ                                                                \
	12000000U // TODO uses PMC which is secure: CLOCK_GetFreq(kCLOCK_HsLspi)
#define EXAMPLE_SPI_SSEL 1
#define EXAMPLE_SPI_SPOL kSPI_SpolActiveAllLow

#if (SENSOR_TASK_RANDOM != 1)
static int8_t sensor_init(struct bme280_dev *dev);
static void delay_us(uint32_t delay_us, void *intf_ptr);
static void spi_init(void);
#endif
static void print_sensor_data(struct bme280_data *comp_data);

/**
 * This task just prints a cyclic message as a demonstration
 * @param params FreeRTOS task parameters, can be NULL
 */
void sensor_task(void *params)
{
	uint32_t data_index = 0;

	VERB("(SENSOR) task waiting for network connection\n");

	// Wait until network connection is established
	ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(portMAX_DELAY));

	VERB("(SENSOR) task waiting for 3s\n");

	vTaskDelay(pdMS_TO_TICKS(3000));

	VERB("(SENSOR) task initializing sensor\n");

#if (SENSOR_TASK_RANDOM != 1)
	struct bme280_dev dev;
	sensor_init(&dev);
#endif

	TickType_t last_wake_time = xTaskGetTickCount();
	for (;;) {
		struct bme280_data comp_data;
#if (SENSOR_TASK_RANDOM != 1)
		// Delay while the sensor completes a measurement
		VERB("(SENSOR) Task waiting\n");
		dev.delay_us(SENSOR_TASK_WAIT_MS * 1000, dev.intf_ptr);
		VERB("(SENSOR) task collecting data\n");
		int8_t ret = bme280_get_sensor_data(BME280_ALL, &comp_data, &dev);
		if (ret != BME280_OK) {
			ERROR("(SENSOR) Failed to collect sensor data\n");
		}
#else
		uint8_t rnd[4];
		lzport_rng_get_random_data(rnd, sizeof(rnd));
		comp_data.temperature = (double)((uint16_t)((rnd[1] << 8) | rnd[0]) / 1000.0f);
		static int humidity = 0;
		comp_data.humidity = (double)(humidity++);
#endif
		VERB("(SENSOR) task collected data\n");
		print_sensor_data(&comp_data);
		lz_net_sensor_data_t sensor_data = { .index = data_index++,
											 .temperature = comp_data.temperature,
											 .humidity = comp_data.humidity };

		VERB("(SENSOR) Queueing sensor data\n");

		net_send_data(sensor_data);

		vTaskDelayUntil(&last_wake_time, pdMS_TO_TICKS(get_interval()));
	}
}

static void print_sensor_data(struct bme280_data *comp_data)
{
	VERB("(SENSOR) Temperature:  %d C, Pressure: %d hPA, Humidity %d pct\n",
		 (uint32_t)comp_data->temperature, (uint32_t)comp_data->pressure / 1000,
		 (uint32_t)comp_data->humidity);
}

#if (SENSOR_TASK_RANDOM != 1)
static int8_t sensor_init(struct bme280_dev *dev)
{
	// Sensor 0 interface over 4-wire SPI
	uint8_t dev_addr = 0;
	int8_t ret = BME280_OK;
	uint8_t settings;

	VERB("(SENSOR) Initializing SPI\n");
	spi_init();
	VERB("(SENSOR) Initializing BME280\n");

	dev->intf_ptr = &dev_addr;
	dev->intf = BME280_SPI_INTF;
	dev->read = spi_read;
	dev->write = spi_write;
	dev->delay_us = delay_us;

	if ((ret = bme280_init(dev)) != BME280_OK) {
		ERROR("(SENSOR) Failed to init BME280. Ret = %x\n", (int32_t)ret);
		goto out;
	}

	// Mode of operation: indoot navigation mode
	dev->settings.osr_h = BME280_OVERSAMPLING_1X;
	dev->settings.osr_p = BME280_OVERSAMPLING_16X;
	dev->settings.osr_t = BME280_OVERSAMPLING_2X;
	dev->settings.filter = BME280_FILTER_COEFF_16;
	dev->settings.standby_time = BME280_STANDBY_TIME_62_5_MS;

	settings = BME280_OSR_PRESS_SEL;
	settings |= BME280_OSR_TEMP_SEL;
	settings |= BME280_OSR_HUM_SEL;
	settings |= BME280_STANDBY_SEL;
	settings |= BME280_FILTER_SEL;

	if ((ret = bme280_set_sensor_settings(settings, dev)) != BME280_OK) {
		ERROR("(SENSOR) Failed to set BME280 settings. Ret = %hhd\n", ret);
		goto out;
	}

	if ((ret = bme280_set_sensor_mode(BME280_NORMAL_MODE, dev)) != BME280_OK) {
		ERROR("(SENSOR) Failed to set BME280 sensor mode. Ret = %hhd\n", ret);
		goto out;
	}

out:
	return ret;
}

static void delay_us(uint32_t delay_us, void *intf_ptr)
{
	vTaskDelay(pdMS_TO_TICKS(delay_us / 1000));
}

static void spi_init(void)
{
	// TODO init pins

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

int8_t spi_read(uint8_t reg_addr, uint8_t *reg_data, uint32_t len, void *intf_ptr)
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

int8_t spi_write(uint8_t reg_addr, const uint8_t *reg_data, uint32_t len, void *intf_ptr)
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

#endif