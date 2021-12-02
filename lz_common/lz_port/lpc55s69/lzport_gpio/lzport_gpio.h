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

#ifndef lzport_GPIO_H_
#define lzport_GPIO_H_

#define LED_ON 1
#define LED_OFF 0
#define LED_FAIL 0
#define LED_OK 1

void lzport_gpio_port_init(void);
void lzport_gpio_trace_init(void);
;
void lzport_gpio_led_init(void);
void lzport_gpio_set_status_led(bool status, bool state);
void lzport_gpio_set_blue_led(bool state);
void lzport_gpio_toggle_trace(void);
void lzport_pio_set_trace(bool status);
void lzport_gpio_set_all_leds(bool state);
void lzport_gpio_rts_init(void);
void lzport_gpio_set_rts(bool status);
void lzport_gpio_set_trace(void);
void lzport_gpio_reset_trace(void);

#endif /* lzport_GPIO_H_ */
