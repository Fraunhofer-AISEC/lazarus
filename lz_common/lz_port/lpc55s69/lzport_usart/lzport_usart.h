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

#ifndef RE_USART_H
#define RE_USART_H

#define ESP_USART USART2
#define ESP_USART_CLK_SRC kCLOCK_Flexcomm2
// TODO CLOCK_GetFreq(kCLOCK_Flexcomm2) is not available, as it unnecessarily accesses
// the PMC which is only accessible in the secure world. If kCLOCK_Flexcomm2 changes
// this must be adjusted manually
#define ESP_USART_CLK_FREQ 12000000U
#define ESP_USART_IRQHandler FLEXCOMM2_IRQHandler
#define ESP_USART_IRQn FLEXCOMM2_IRQn
#define ESP_USART_BAUD_RATE 115200U
#define USART_BUFF_SIZE 2000

// Types ===========================================================================================

/**
 * @brief 	USART circular buffer structure
 */
typedef struct {
	uint16_t size;
	uint16_t start;
	uint16_t end;
	uint8_t elems[USART_BUFF_SIZE + 1];
} lzport_usart_fifo_t;

// Declarations ======================================================================================
extern volatile lzport_usart_fifo_t lzport_usart_tx_fifo_esp;
extern volatile lzport_usart_fifo_t lzport_usart_rx_fifo_esp;

void lzport_usart_init_esp(void);

void lzport_usart_buffer_init(volatile lzport_usart_fifo_t *buffer);
void lzport_usart_buffer_write(volatile lzport_usart_fifo_t *buffer, uint8_t elem);
void lzport_usart_buffer_read(volatile lzport_usart_fifo_t *buffer, uint8_t *elem);
int lzport_usart_buffer_is_full(volatile lzport_usart_fifo_t *buffer);
int lzport_usart_buffer_is_empty(volatile lzport_usart_fifo_t *buffer);

#endif /* RE_USART_H */
