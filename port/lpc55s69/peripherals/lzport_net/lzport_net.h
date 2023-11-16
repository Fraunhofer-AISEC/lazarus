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

#ifndef LZPORT_NET_H_
#define LZPORT_NET_H_

/*******************************************
 * Error Handling
 *******************************************/
typedef uint32_t NET_RESULT;

#define NET_SUCCESS 0x00000000

#define NET_ERROR 0xFFFFFF0F
#define NET_ERROR_BUSY 0xFFFFFF0E
#define NET_ERROR_ALREADY_CONNECTED 0xFFFFFF0D
#define NET_ERROR_TIMEOUT 0xFFFFFF0C

NET_RESULT lzport_net_init(uint8_t *ip, uint8_t *mac, char *ssid, char *pwd);

NET_RESULT lzport_net_reset(void);

NET_RESULT lzport_socket_close(uint32_t handle, uint32_t timeout_ms);
NET_RESULT lzport_socket_open(uint32_t handle, const char *host_name, uint32_t dest_port,
							 uint32_t timeout_ms);
NET_RESULT lzport_socket_send(uint32_t handle, uint8_t *data, uint32_t len, uint32_t timeout_ms);
NET_RESULT lzport_socket_receive(uint32_t handle, uint8_t *data, uint32_t len_exp,
								uint32_t timeout_ms, uint32_t *len_rec);

#if (1 == FREERTOS_AVAILABLE)
NET_RESULT lzport_esp8266_init_queue(void);
NET_RESULT lzport_esp8266_queue_send(char ch, uint32_t *higher_prio_task_woken);
#endif

#endif /* lzport_ESP_SOCKET_NEW_H_ */
