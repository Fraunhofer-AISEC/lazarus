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
#include "stdio.h"
#include "FreeRTOS.h"
#include "task.h"

#include "lz_config.h"
#include "lzport_gpio.h"
#include "lzport_debug_output.h"
#include "lzport_spi.h"
#include "lz_common.h"
#include "lz_flash_handler.h"
#include "lz_awdt.h"
#include "lz_net.h"

#include "benchmark.h"
#include "net.h"
#include "bme280.h"
#include "sensor.h"

#define SENSOR_TASK_WAIT_MS 3000

static TaskHandle_t sensor_task_handle = NULL;

typedef struct {
	uint32_t index;
	float temp;
	float humidity;
} sensor_data_t;

static sensor_data_t sensor_data = { 0 };

static int8_t sensor_init(struct bme280_dev *dev);
static void delay_us(uint32_t delay_us, void *intf_ptr);
static void spi_init(void);
static void print_sensor_data(struct bme280_data *comp_data);

/**
 * This task just prints a cyclic message as a demonstration
 * @param params FreeRTOS task parameters, can be NULL
 */
void sensor_task(void *params)
{
	sensor_task_handle = xTaskGetCurrentTaskHandle();

	dbgprint(DBG_SENSOR, "INFO: Sensor task waiting for network connection\n");

	// Wait until network connection is established
	ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(portMAX_DELAY));

	dbgprint(DBG_SENSOR, "INFO: Sensor task waiting for 3s\n");

	vTaskDelay(pdMS_TO_TICKS(3000));

	dbgprint(DBG_SENSOR, "INFO: Sensor task initializing sensor\n");

	struct bme280_dev dev;
	sensor_init(&dev);

	for (;;) {
		// TODO sensor data currently in AWDT task to avoid queues
		struct bme280_data comp_data;
		// Delay while the sensor completes a measurement
		dbgprint(DBG_SENSOR, "INFO: Sensor Task waiting\n");
		dev.delay_us(SENSOR_TASK_WAIT_MS * 1000, dev.intf_ptr);
		dbgprint(DBG_SENSOR, "INFO: Sensor task collecting data\n");
		int8_t ret = bme280_get_sensor_data(BME280_ALL, &comp_data, &dev);
		if (ret != BME280_OK) {
			dbgprint(DBG_ERR, "ERROR: Failed to collect sensor data\n");
		}
		dbgprint(DBG_SENSOR, "INFO: Sensor task collected data\n");
		print_sensor_data(&comp_data);
		sensor_data.index++;
		sensor_data.humidity = comp_data.humidity;
		sensor_data.temp = comp_data.temperature;
	}
}

TaskHandle_t get_sensor_task_handle(void)
{
	return sensor_task_handle;
}

void send_sensor_data(void)
{
	lz_net_send_data((uint8_t *)&sensor_data, sizeof(sensor_data_t));
}

static void print_sensor_data(struct bme280_data *comp_data)
{
	dbgprint(DBG_SENSOR, "Temperature:  %d C\nPressure: %d hPA\nHumidity %d pct\n\n",
			 (uint32_t)comp_data->temperature, (uint32_t)comp_data->pressure / 1000,
			 (uint32_t)comp_data->humidity);
}

static int8_t sensor_init(struct bme280_dev *dev)
{
	// Sensor 0 interface over 4-wire SPI
	uint8_t dev_addr = 0;
	int8_t ret = BME280_OK;
	uint8_t settings;

	dbgprint(DBG_SENSOR, "INFO: SENSOR INIT 1\n");
	lzport_spi_init();
	dbgprint(DBG_SENSOR, "INFO: SENSOR INIT 2\n");

	dev->intf_ptr = &dev_addr;
	dev->intf = BME280_SPI_INTF;
	dev->read = lzport_spi_read;
	dev->write = lzport_spi_write;
	dev->delay_us = delay_us;

	if ((ret = bme280_init(dev)) != BME280_OK) {
		dbgprint(DBG_ERR, "ERROR: Failed to init BME280. Ret = %d\n", ret);
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
		dbgprint(DBG_ERR, "ERROR: Failed to set BME280 settings. Ret = %d\n", ret);
		goto out;
	}

	if ((ret = bme280_set_sensor_mode(BME280_NORMAL_MODE, dev)) != BME280_OK) {
		dbgprint(DBG_SENSOR, "ERROR: Failed to set BME280 sensor mode. Ret = %d\n", ret);
		goto out;
	}

out:
	return ret;
}

static void delay_us(uint32_t delay_us, void *intf_ptr)
{
	vTaskDelay(pdMS_TO_TICKS(delay_us / 1000));
}