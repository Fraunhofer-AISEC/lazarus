// Copyright(c) 2022 Fraunhofer AISEC

#pragma once

void sensor_task(void* params);
void send_sensor_data(void);
TaskHandle_t get_sensor_task_handle(void);

int8_t spi_write(uint8_t reg_addr, const uint8_t *reg_data, uint32_t len, void *intf_ptr);
int8_t spi_read(uint8_t reg_addr, uint8_t *reg_data, uint32_t len, void *intf_ptr);
