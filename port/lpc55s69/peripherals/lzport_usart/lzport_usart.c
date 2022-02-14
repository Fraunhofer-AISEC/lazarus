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
#include "fsl_usart.h"

#include "lz_config.h"
#include "lzport_usart.h"
#include "lzport_debug_output.h"

#if (1 == FREERTOS_AVAILABLE)
#include "FreeRTOS.h"
#include "task.h"
#include "lzport_net.h"
#endif

volatile FILE *net_fd = NULL;
volatile lzport_usart_fifo_t lzport_usart_tx_fifo_esp;
volatile lzport_usart_fifo_t lzport_usart_rx_fifo_esp;

void lzport_usart_init_esp(void)
{
	usart_config_t config;

	lzport_usart_buffer_init(&lzport_usart_tx_fifo_esp);
#if (1 == FREERTOS_AVAILABLE)
	if (lzport_esp8266_init_queue() != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: Failed to initialize ESP queue\n");
		for (;;)
			;
	}
#else
	lzport_usart_buffer_init(&lzport_usart_rx_fifo_esp);
#endif

	CLOCK_AttachClk(kFRO12M_to_FLEXCOMM2);

	USART_GetDefaultConfig(&config);
	config.baudRate_Bps = ESP_USART_BAUD_RATE;
	config.enableTx = true;
	config.enableRx = true;
	USART_Init(ESP_USART, &config, ESP_USART_CLK_FREQ);

	net_fd = fopen("wifi", "wb");

	USART_EnableInterrupts(ESP_USART,
						   kUSART_RxLevelInterruptEnable | kUSART_RxErrorInterruptEnable);
	EnableIRQ(ESP_USART_IRQn);
}

void lzport_usart_buffer_init(volatile lzport_usart_fifo_t *buffer)
{
	buffer->size = USART_BUFF_SIZE + 1;
	buffer->start = 0;
	buffer->end = 0;
}

int lzport_usart_buffer_is_full(volatile lzport_usart_fifo_t *buffer)
{
	return (buffer->end + 1) % buffer->size == buffer->start;
}

int lzport_usart_buffer_is_empty(volatile lzport_usart_fifo_t *buffer)
{
	return buffer->end == buffer->start;
}

void lzport_usart_buffer_write(volatile lzport_usart_fifo_t *buffer, uint8_t elem)
{
	buffer->elems[buffer->end] = elem;
	buffer->end = (buffer->end + 1) % buffer->size;

	// if buffer is full
	if (buffer->end == buffer->start) {
		buffer->start = (buffer->start + 1) % buffer->size;
	}
}

void lzport_usart_buffer_read(volatile lzport_usart_fifo_t *buffer, uint8_t *elem)
{
	*elem = buffer->elems[buffer->start];
	buffer->start = (buffer->start + 1) % buffer->size;
}

void ESP_USART_IRQHandler(void)
{
	if ((kUSART_RxFifoNotEmptyFlag)&USART_GetStatusFlags(ESP_USART)) {
		uint8_t byte = USART_ReadByte(ESP_USART);

#if (1 == FREERTOS_AVAILABLE)
		uint32_t higher_prio_task_woken = 0;
		if (lzport_esp8266_queue_send(byte, &higher_prio_task_woken) != LZ_SUCCESS) {
			dbgprint(DBG_ERR, "ERROR: Failed to send to queue from ESP USART\n");
		}
		portYIELD_FROM_ISR(higher_prio_task_woken);
#else
		lzport_usart_buffer_write(&lzport_usart_rx_fifo_esp, byte);
#endif
	} else if (kUSART_RxError & USART_GetStatusFlags(ESP_USART)) {
		dbgprint(DBG_ERR, "ERROR: ESP USART. Looping forever\n");
		for (;;)
			;
	} else if (kUSART_TxFifoNotFullFlag & USART_GetStatusFlags(ESP_USART)) {
		if (!lzport_usart_buffer_is_empty(&lzport_usart_tx_fifo_esp)) {
			uint8_t ch;
			lzport_usart_buffer_read(&lzport_usart_tx_fifo_esp, &ch);
			USART_WriteByte(ESP_USART, ch);
		}
		if (lzport_usart_buffer_is_empty(&lzport_usart_tx_fifo_esp)) {
			USART_DisableInterrupts(ESP_USART, kUSART_TxLevelInterruptEnable);
		}
	}
}
