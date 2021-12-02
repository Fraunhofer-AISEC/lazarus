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
#include "string.h"
#include "stdio.h"

#include "lz_config.h"
#include "lz_common/lz_error.h"
#include "lzport_systick_delay/lzport_systick_delay.h"
#include "lzport_debug_output/lzport_debug_output.h"
#include "lzport_usart/lzport_usart.h"
#if (1 == FREERTOS_AVAILABLE)
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#else
#include "lzport_systick_delay/lzport_systick_delay.h"
#endif

#include "lzport_net/lzport_net.h"

#define ESP8266_STD_TIMEOUT_MS 2000
#define TIMEOUT_TCP_MS 10000
#define ESP8266_EXT_TIMEOUT_MS 25000
#define ESP8266_RCV_QUEUE_SIZE 8096

#define NW_STATUS_CONNECTED 2
#define NW_STATUS_TCP_TRANSMISSION 3
#define NW_STATUS_TCP_DISCONNECTED 4
#define NW_STATUS_DISCONNECTED 5

#define LEN_IP 4
#define LEN_MAC 6

extern FILE *net_fd;
static char rxbuf[8096] = { 0 };

#if (1 == FREERTOS_AVAILABLE)
static QueueHandle_t esp8266_rcv_queue;
#endif

const char *response_ok = "OK\r\n";
const char *response_sendok = "SEND OK\r\n";
const char *response_err = "ERROR\r\n";
const char *response_already_connected = "ALREADY CONNECTED\r\n\r\nERROR\r\n";
const char *response_busy_p = "busy p...\r\n";
const char *response_busy_s = "busy s...\r\n";
const char *response_send_ready = ">";
const char *response_recv_ready = ":";
const char *response_closed = "CLOSED\r\n";

static LZ_RESULT esp8266_connect_to_ap(char *ssid, char *pwd);
static LZ_RESULT esp8266_get_network_info(uint8_t *ip, uint32_t iplen, uint8_t *mac,
										  uint32_t maclen);
static LZ_RESULT esp8266_receive(char *buf, uint32_t buf_size, const char *terminator,
								 uint32_t timeout_ms);
static LZ_RESULT esp8266_receive_data(char *buf, uint32_t buf_size, uint32_t timeout_ms);
static void update_remaining_time(uint32_t *remaining_time, uint32_t elapsed_time);

LZ_RESULT lzport_net_init(uint8_t *ip, uint8_t *mac, char *ssid, char *pwd)
{
	LZ_RESULT result = LZ_ERROR;

	fprintf(net_fd, "ATE0\r\n");
	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, ESP8266_STD_TIMEOUT_MS) != LZ_SUCCESS) {
		dbgprint(DBG_ERR, "ERROR: ESP does not respond to ATE0 command\n");
		return result;
	}

	fprintf(net_fd, "AT+CIPSTATUS\r\n");
	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, ESP8266_STD_TIMEOUT_MS) != LZ_SUCCESS) {
		return result;
	}

	uint32_t status;
	sscanf(rxbuf, "STATUS:%lu\r\n", &status);

	if (status != NW_STATUS_DISCONNECTED) {
		fprintf(net_fd, "AT+CWJAP?\r\n");
		if (esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, ESP8266_STD_TIMEOUT_MS) !=
			LZ_SUCCESS) {
			return result;
		}

		if (!strstr(rxbuf, ssid)) {
			dbgprint(DBG_NW, "WARN: ESP8266 connected to wrong access point\n");

			if (esp8266_connect_to_ap(ssid, pwd) != LZ_SUCCESS) {
				return result;
			}
		}

		if (status == NW_STATUS_TCP_TRANSMISSION) {
			lzport_socket_close(0, TIMEOUT_TCP_MS);
		}
	} else {
		if (esp8266_connect_to_ap(ssid, pwd) != LZ_SUCCESS) {
			return result;
		}
	}

	if (esp8266_get_network_info(ip, LEN_IP, mac, LEN_MAC) != LZ_SUCCESS) {
		return result;
	}

	fprintf(net_fd, "AT+CWAUTOCONN=1\r\n");
	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, ESP8266_STD_TIMEOUT_MS) != LZ_SUCCESS) {
		return result;
	}

	fprintf(net_fd, "AT+CIPMUX=1\r\n");
	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, ESP8266_STD_TIMEOUT_MS) != LZ_SUCCESS) {
		return result;
	}

	dbgprint(DBG_NW, "ESP8266 successfully connected to %s\n", ssid);

	result = LZ_SUCCESS;

	return result;
}

LZ_RESULT lzport_socket_open(uint32_t handle, const char *host_name, uint32_t dest_port,
							 uint32_t timeout_ms)
{
	uint32_t curr_time_ms = lzport_get_tick_ms();
	uint32_t remaining_time_ms = timeout_ms;
	LZ_RESULT result;

	while (remaining_time_ms > 0) {
		update_remaining_time(&remaining_time_ms, lzport_get_tick_ms() - curr_time_ms);
		curr_time_ms = lzport_get_tick_ms();

		fprintf(net_fd, "AT+CIPSTART=%ld,\"%s\",\"%s\",%ld\r\n", handle, "TCP", host_name,
				dest_port);

		result = esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, remaining_time_ms);

		if (result == LZ_SUCCESS) {
			return LZ_SUCCESS;
		}

#if (1 == LZ_DBG_NETWORK)
		lzport_gpio_toggle_trace();
#endif

		if (result == LZ_ERROR_ESP_ALREADY_CONN) {
			dbgprint(DBG_WARN, "WARN: Socket is already open\n");
			return LZ_SUCCESS;
		} else if (result == LZ_ERROR_ESP_BUSY) {
			dbgprint(DBG_WARN, "WARN: Failed to open socket, ESP busy. Wait until finished..\n");
			if (esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, remaining_time_ms) !=
				LZ_SUCCESS) {
				dbgprint(DBG_WARN, "WARN: ESP did not finish until timeout\n");
			}
		} else if (result == LZ_ERROR_ESP_ERROR) {
			if (esp8266_receive(rxbuf, sizeof(rxbuf), response_closed, remaining_time_ms) ==
				LZ_SUCCESS) {
				dbgprint(DBG_WARN, "WARN: Failed to open socket. ESP returned %s\n", rxbuf);

				uint32_t status;
				sscanf(rxbuf, "STATUS:%lu\r\n", &status);
			} else {
				dbgprint(DBG_WARN, "WARN: Failed to open socket. ESP returned %s\n", rxbuf);
			}
		} else {
			dbgprint(DBG_WARN, "WARN: Failed to open socket. ESP returned %s\n", rxbuf);
		}
	}

	dbgprint(DBG_WARN, "WARN: Timeout opening socket\n");

	return LZ_ERROR;
}

LZ_RESULT lzport_socket_close(uint32_t handle, uint32_t timeout_ms)
{
	fprintf(net_fd, "AT+CIPCLOSE=%ld\r\n", handle);
	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, timeout_ms) != LZ_SUCCESS) {
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

LZ_RESULT lzport_socket_send(uint32_t handle, uint8_t *data, uint32_t len, uint32_t timeout_ms)
{
	uint32_t curr_time_ms = lzport_get_tick_ms();
	uint32_t remaining_time_ms = timeout_ms;

	dbgprint(DBG_NW, "esp8266_socket_send\n");

	dbgprint(DBG_NW, "AT+CIPSEND=%ld,%ld\n", handle, len);
	fprintf(net_fd, "AT+CIPSEND=%ld,%ld\r\n", handle, len);

	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, remaining_time_ms) != LZ_SUCCESS) {
		return LZ_ERROR;
	}

	update_remaining_time(&remaining_time_ms, lzport_get_tick_ms() - curr_time_ms);
	curr_time_ms = lzport_get_tick_ms();

	dbgprint(DBG_NW, "esp8266_socket_send: Waiting for ESP to be ready for transmission\n");

	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_send_ready, remaining_time_ms) !=
		LZ_SUCCESS) {
		return LZ_ERROR;
	}

	dbgprint(DBG_NW, "\nesp8266_socket_send: Starting to send %d bytes\n", len);

	uint32_t sent = fwrite(data, 1, len, net_fd);
	fflush(net_fd);
	if (len != sent) {
		dbgprint(DBG_NW,
				 "WARN: esp8266_socket_send: Failed to send %d bytes (only sent %d bytes)\n", len,
				 sent);
		return LZ_ERROR;
	}

	update_remaining_time(&remaining_time_ms, lzport_get_tick_ms() - curr_time_ms);
	curr_time_ms = lzport_get_tick_ms();

	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_sendok, remaining_time_ms) != LZ_SUCCESS) {
		dbgprint(DBG_WARN, "esp8266_socket_send error: timeout waiting for 'SEND OK'\n");
		return LZ_ERROR;
	}

	dbgprint(DBG_NW, "esp8266_socket_send: success\n");

	return LZ_SUCCESS;
}

LZ_RESULT lzport_socket_receive(uint32_t handle, uint8_t *data, uint32_t len_exp,
								uint32_t timeout_ms, uint32_t *len_rec)
{
	uint32_t curr_time_ms = lzport_get_tick_ms();
	uint32_t remaining_time_ms = timeout_ms;
	uint32_t handle_recv;

	dbgprint(DBG_NW, "INFO: ESP8266 - Receiving packet header\n");

	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_recv_ready, remaining_time_ms) !=
		LZ_SUCCESS) {
		dbgprint(DBG_NW, "ERROR: ESP8266 - Failed to receive header from ESP8266\n");
		return LZ_ERROR;
	}

	dbgprint(DBG_NW, "INFO: ESP8266 - received start sequence: %s\n", rxbuf);

	uint32_t ret = sscanf((char *)&rxbuf[2], "+IPD,%ld,%ld:", &handle_recv, len_rec);

	if ((ret != 2) || (handle_recv != handle)) {
		dbgprint(DBG_ERR, "WARN: ESP8266 - Failed to parse start sequence\n");
		return LZ_ERROR;
	}

	if (len_exp < *len_rec) {
		dbgprint(DBG_ERR, "WARN: ESP8266 - Receive buffer too small. Expected = %d, +IPD = %d\n",
				 len_exp, *len_rec);
		return LZ_ERROR;
	}

	if (len_exp > *len_rec) {
		dbgprint(DBG_NW,
				 "INFO: ESP8266 - Packet to be received is smaller than "
				 "specified length (%d vs. %d)\n",
				 *len_rec, len_exp);
	}

	update_remaining_time(&remaining_time_ms, lzport_get_tick_ms() - curr_time_ms);
	curr_time_ms = lzport_get_tick_ms();

	dbgprint(DBG_NW, "INFO: ESP8266 - Receiving %d bytes\n", *len_rec);

	if (esp8266_receive_data((char*)data, *len_rec, remaining_time_ms) != LZ_SUCCESS) {
		dbgprint(DBG_NW, "ERROR: ESP8266 - Failed to receive data from\n");
		return LZ_ERROR;
	}

	dbgprint(DBG_NW, "INFO: ESP8266 successfully received data from socket\n");

	return LZ_SUCCESS;
}

#if (1 == FREERTOS_AVAILABLE)

LZ_RESULT lzport_esp8266_init_queue(void)
{
	esp8266_rcv_queue = xQueueCreate(ESP8266_RCV_QUEUE_SIZE, sizeof(char));
	if (esp8266_rcv_queue == NULL) {
		return LZ_ERROR;
	}
	return LZ_SUCCESS;
}

LZ_RESULT lzport_esp8266_queue_send(char ch, uint32_t *higher_prio_task_woken)
{
	if (xQueueSendFromISR(esp8266_rcv_queue, &ch, (BaseType_t *)higher_prio_task_woken) != pdPASS) {
		return LZ_ERROR;
	}
	return LZ_SUCCESS;
}

#endif

#if (1 == FREERTOS_AVAILABLE)

static LZ_RESULT esp8266_receive(char *buf, uint32_t buf_size, const char *terminator,
								 uint32_t timeout_ms)
{
	uint32_t remaining_timeout = pdMS_TO_TICKS(timeout_ms);
	uint32_t curr_time = xTaskGetTickCount();
	uint32_t received_len = 0;

	memset(buf, 0x00, buf_size);

	if (buf_size < strlen(terminator) + 1) {
		return LZ_ERROR;
	}

	dbgprint(DBG_NW, "INFO: esp8266_receive receiving data\n");

	char ch;
	while (xQueueReceive(esp8266_rcv_queue, &ch, (TickType_t)remaining_timeout) == pdPASS) {
		buf[received_len] = ch;
		received_len = received_len + 1;

		uint32_t elapsed_time = (xTaskGetTickCount() - curr_time);
		if (remaining_timeout > elapsed_time) {
			remaining_timeout -= elapsed_time;
		} else {
			remaining_timeout = 0;
		}
		curr_time = xTaskGetTickCount();

		if ((received_len >= strlen(terminator)) && strstr(buf, terminator)) {
			return LZ_SUCCESS;
		} else if ((received_len >= strlen(response_already_connected)) &&
				   strstr(buf, response_already_connected)) {
			dbgprint(DBG_WARN, "WARN: ESP responded with already connected\n");
			return LZ_ERROR_ESP_ALREADY_CONN;
		} else if ((received_len >= strlen(response_err)) && strstr(buf, response_err)) {
			dbgprint(DBG_WARN, "WARN: ESP responded with ERROR\n");
			return LZ_ERROR_ESP_ERROR;
		} else if (((received_len >= strlen(response_busy_p)) && strstr(buf, response_busy_p)) ||
				   ((received_len >= strlen(response_busy_s)) && strstr(buf, response_busy_s))) {
			dbgprint(DBG_WARN, "WARN: ESP responded with BUSY\n");
			return LZ_ERROR_ESP_BUSY;
		}

		if (received_len >= buf_size) {
			dbgprint(DBG_WARN, "\nERROR: ESP8266 Buffer full while waiting for terminator\n");
			return LZ_ERROR;
		}
	}

	dbgprint(DBG_WARN, "WARN: Timeout waiting for ESP8266 response\n");

	return LZ_TIMEOUT;
}

static LZ_RESULT esp8266_receive_data(char *buf, uint32_t buf_size, uint32_t timeout_ms)
{
	uint32_t remaining_timeout = pdMS_TO_TICKS(timeout_ms);
	uint32_t curr_time = xTaskGetTickCount();
	uint32_t received_len = 0;

	memset(buf, 0x00, buf_size);

	dbgprint(DBG_NW, "INFO: In esp8266_receive_data\n");

	char ch;
	while (xQueueReceive(esp8266_rcv_queue, &ch, (TickType_t)remaining_timeout) == pdPASS) {
		buf[received_len] = ch;
		received_len = received_len + 1;

		uint32_t elapsed_time = (xTaskGetTickCount() - curr_time);
		if (remaining_timeout > elapsed_time) {
			remaining_timeout -= elapsed_time;
		} else {
			remaining_timeout = 0;
		}
		curr_time = xTaskGetTickCount();

		if (received_len == buf_size) {
			return LZ_SUCCESS;
		}
	}

	dbgprint(DBG_WARN, "WARN: Timeout waiting for ESP8266 response\n");

	return LZ_ERROR;
}

#else

static LZ_RESULT esp8266_receive(char *buf, uint32_t buf_size, const char *terminator,
								 uint32_t timeout_ms)
{
	uint32_t deadline = lzport_get_tick_ms() + timeout_ms;
	uint32_t received_len = 0;

	memset(buf, 0x00, buf_size);

	if (buf_size < strlen(terminator) + 1) {
		return LZ_ERROR;
	}

	dbgprint(DBG_NW, "ESP8266: ");

	while (deadline >= lzport_get_tick_ms()) {
		if (!lzport_usart_buffer_is_empty(&lzport_usart_rx_fifo_esp)) {
			uint8_t c;
			lzport_usart_buffer_read(&lzport_usart_rx_fifo_esp, &c);
			dbgprint(DBG_NW, "%c", c);
			buf[received_len] = (char)c;
			received_len++;
		}

		if ((received_len >= strlen(terminator)) && strstr(buf, terminator)) {
			return LZ_SUCCESS;
		} else if ((received_len >= strlen(response_already_connected)) &&
				   strstr(buf, response_already_connected)) {
			dbgprint(DBG_WARN, "WARN: ESP responded with already connected\n");
			return LZ_ERROR_ESP_ALREADY_CONN;
		} else if ((received_len >= strlen(response_err)) && strstr(buf, response_err)) {
			dbgprint(DBG_WARN, "WARN: ESP responded with ERROR\n");
			return LZ_ERROR_ESP_ERROR;
		} else if (((received_len >= strlen(response_busy_p)) && strstr(buf, response_busy_p)) ||
				   ((received_len >= strlen(response_busy_s)) && strstr(buf, response_busy_s))) {
			dbgprint(DBG_WARN, "WARN: ESP responded with BUSY\n");
			return LZ_ERROR_ESP_BUSY;
		}
		if (received_len >= buf_size) {
			dbgprint(DBG_WARN, "WARN: specified receive buffer full\n");
			return LZ_ERROR;
		}
	}

	dbgprint(DBG_WARN, "WARN: Timeout waiting for ESP8266 response\n");

	return LZ_ERROR;
}

static LZ_RESULT esp8266_receive_data(char *buf, uint32_t buf_size, uint32_t timeout_ms)
{
	uint32_t deadline = lzport_get_tick_ms() + timeout_ms;
	uint32_t received_len = 0;

	memset(buf, 0x00, buf_size);

	dbgprint(DBG_NW, "ESP8266: ");

	while (deadline >= lzport_get_tick_ms()) {
		if (!lzport_usart_buffer_is_empty(&lzport_usart_rx_fifo_esp)) {
			lzport_usart_buffer_read(&lzport_usart_rx_fifo_esp, (uint8_t*)&buf[received_len]);
			dbgprint(DBG_NW, "%c", buf[received_len]);
			received_len++;
		}

		if (received_len == buf_size) {
			return LZ_SUCCESS;
		}
	}

	dbgprint(DBG_WARN, "WARN: Timeout waiting for ESP8266 response\n");

	return LZ_ERROR;
}

#endif

static LZ_RESULT esp8266_connect_to_ap(char *ssid, char *pwd)
{
	dbgprint(DBG_NW, "AT+CWMODE_DEF=1\n");
	fprintf(net_fd, "AT+CWMODE_DEF=1\r\n");
	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, ESP8266_STD_TIMEOUT_MS) != LZ_SUCCESS) {
		return LZ_ERROR;
	}

	dbgprint(DBG_NW, "AT+CWLAP\n");
	fprintf(net_fd, "AT+CWLAP\r\n");
	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, ESP8266_EXT_TIMEOUT_MS) != LZ_SUCCESS) {
		return LZ_ERROR;
	}

	if (!strstr(rxbuf, ssid)) {
		dbgprint(DBG_NW, "AT+CWLAP: Wi-Fi AP not detected (%s)\n", ssid);
	}

	dbgprint(DBG_NW, "AT+CWJAP_DEF=\"%s\",\"%s\"\n", ssid, (pwd == NULL) ? "" : pwd);
	fprintf(net_fd, "AT+CWJAP_DEF=\"%s\",\"%s\"\r\n", ssid, (pwd == NULL) ? "" : pwd);
	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, ESP8266_EXT_TIMEOUT_MS) != LZ_SUCCESS) {
		return LZ_ERROR;
	}

	return LZ_SUCCESS;
}

static LZ_RESULT esp8266_get_network_info(uint8_t *ip, uint32_t iplen, uint8_t *mac,
										  uint32_t maclen)
{
	if ((iplen != LEN_IP) || (maclen != 6)) {
		dbgprint(DBG_WARN, "WARN: Specified IP or MAC address length is invalid\n");
		return LZ_ERROR;
	}

	fprintf(net_fd, "AT+CIFSR\r\n");
	if (esp8266_receive(rxbuf, sizeof(rxbuf), response_ok, ESP8266_STD_TIMEOUT_MS) != LZ_SUCCESS) {
		return LZ_ERROR;
	}

	uint32_t iptmp[LEN_IP] = { 0 };
	uint32_t mactmp[LEN_MAC] = { 0 };
	if (sscanf(rxbuf,
			   "+CIFSR:STAIP,\"%lu.%lu.%lu.%lu\"\r\n+CIFSR:STAMAC,"
			   "\"%lx:%lx:%lx:%lx:%lx:%lx:\"\r\n",
			   &iptmp[0], &iptmp[1], &iptmp[2], &iptmp[3], &mactmp[0], &mactmp[1], &mactmp[2],
			   &mactmp[3], &mactmp[4], &mactmp[5]) != 10) {
		dbgprint(DBG_WARN, "WARN: Failed to parse IP and MAC address\n");
		return LZ_ERROR;
	}

	for (uint8_t i = 0; i < LEN_IP; i++) {
		ip[i] = iptmp[i] & 0xFF;
	}
	for (uint8_t i = 0; i < LEN_MAC; i++) {
		mac[i] = mactmp[i] & 0xFF;
	}

	return LZ_SUCCESS;
}

static void update_remaining_time(uint32_t *remaining_time, uint32_t elapsed_time)
{
	if (*remaining_time > elapsed_time) {
		*remaining_time = *remaining_time - elapsed_time;
	} else {
		*remaining_time = 0;
	}
}
