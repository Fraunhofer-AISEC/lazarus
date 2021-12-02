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

#include "board.h"
#include "fsl_gpio.h"
#include "pin_mux.h"
#include "lzport_gpio/lzport_gpio.h"

#define GPIO_LED_BLUE_PORT 1U
#define GPIO_LED_RED_PORT 1U
#define GPIO_LED_GREEN_PORT 1U
#define GPIO_TRACE_OUT_PORT 1U
#define GPIO_LED_BLUE_PIN 4U
#define GPIO_LED_RED_PIN 6U
#define GPIO_LED_GREEN_PIN 7U
#define GPIO_TRACE_OUT_PIN 10U
#define GPIO_TRACE_IN_MODE_DIGITAL 0x01u
#define GPIO_TRACE_IN_FUNC_ALT0 0x00u
#define GPIO_RTS_PORT 1U
#define GPIO_RTS_PIN 9U
#define GPIO_RTS_MODE_DIGITAL 0x01u
#define GPIO_RTS_FUNC_ALT0 0x00u

void lzport_gpio_port_init(void)
{
	GPIO_PortInit(GPIO, 1U);
}

void lzport_gpio_trace_init(void)
{
	gpio_pin_config_t gpio_out_config = {
		kGPIO_DigitalOutput,
		0,
	};
	GPIO_PinInit(GPIO, GPIO_TRACE_OUT_PORT, GPIO_TRACE_OUT_PIN, &gpio_out_config);
	IOCON->PIO[GPIO_TRACE_OUT_PORT][GPIO_TRACE_OUT_PIN] =
		((IOCON->PIO[GPIO_TRACE_OUT_PORT][GPIO_TRACE_OUT_PIN] &
		  (~(IOCON_PIO_FUNC_MASK | IOCON_PIO_DIGIMODE_MASK))) |
		 IOCON_PIO_FUNC(GPIO_TRACE_IN_FUNC_ALT0) | IOCON_PIO_DIGIMODE(GPIO_TRACE_IN_MODE_DIGITAL));
}

void lzport_gpio_rts_init(void)
{
	gpio_pin_config_t gpio_out_config = {
		kGPIO_DigitalOutput,
		0,
	};
	GPIO_PinInit(GPIO, GPIO_RTS_PORT, GPIO_RTS_PIN, &gpio_out_config);
	IOCON->PIO[GPIO_RTS_PORT][GPIO_RTS_PIN] =
		((IOCON->PIO[GPIO_RTS_PORT][GPIO_RTS_PIN] &
		  (~(IOCON_PIO_FUNC_MASK | IOCON_PIO_DIGIMODE_MASK))) |
		 IOCON_PIO_FUNC(GPIO_RTS_FUNC_ALT0) | IOCON_PIO_DIGIMODE(GPIO_RTS_MODE_DIGITAL));
}

void lzport_gpio_led_init(void)
{
	/* Define the init structure for the output LED pin*/
	gpio_pin_config_t led_config = {
		kGPIO_DigitalOutput,
		0,
	};

	/* Init output LED GPIO. */
	GPIO_PinInit(GPIO, GPIO_LED_BLUE_PORT, GPIO_LED_BLUE_PIN, &led_config);
	GPIO_PinInit(GPIO, GPIO_LED_RED_PORT, GPIO_LED_RED_PIN, &led_config);
	GPIO_PinInit(GPIO, GPIO_LED_GREEN_PORT, GPIO_LED_GREEN_PIN, &led_config);

	lzport_gpio_set_status_led(LED_OK, LED_OFF);
	lzport_gpio_set_status_led(LED_FAIL, LED_OFF);
	lzport_gpio_set_blue_led(LED_OFF);
}

void lzport_gpio_set_trace(void)
{
	GPIO_PinWrite(GPIO, GPIO_TRACE_OUT_PORT, GPIO_TRACE_OUT_PIN, 1);
}

void lzport_gpio_reset_trace(void)
{
	GPIO_PinWrite(GPIO, GPIO_TRACE_OUT_PORT, GPIO_TRACE_OUT_PIN, 0);
}

void lzport_gpio_toggle_trace(void)
{
	GPIO->NOT[GPIO_TRACE_OUT_PORT] = 1U << GPIO_TRACE_OUT_PIN;
}

void lzport_gpio_set_rts(bool status)
{
	if (status) {
		GPIO_PortSet(GPIO, GPIO_RTS_PORT, 1u << GPIO_RTS_PIN);
	} else {
		GPIO_PortClear(GPIO, GPIO_RTS_PORT, 1u << GPIO_RTS_PIN);
	}
}

void lzport_gpio_set_status_led(bool status, bool state)
{
	// Turn off red/green LED
	GPIO_PortSet(GPIO, BOARD_LED_RED_GPIO_PORT, 1u << BOARD_LED_RED_GPIO_PIN);
	GPIO_PortSet(GPIO, BOARD_LED_GREEN_GPIO_PORT, 1u << BOARD_LED_GREEN_GPIO_PIN);

	if (state) {
		if (status) {
			// Turn on green LED
			GPIO_PortClear(GPIO, BOARD_LED_GREEN_GPIO_PORT, 1u << BOARD_LED_GREEN_GPIO_PIN);
		} else {
			// Turn on red LED
			GPIO_PortClear(GPIO, BOARD_LED_RED_GPIO_PORT, 1u << BOARD_LED_RED_GPIO_PIN);
		}
	}
}

void lzport_gpio_set_blue_led(bool state)
{
	if (state) {
		GPIO_PortClear(GPIO, BOARD_LED_BLUE_GPIO_PORT, 1u << BOARD_LED_BLUE_GPIO_PIN);
	} else {
		GPIO_PortSet(GPIO, BOARD_LED_BLUE_GPIO_PORT, 1u << BOARD_LED_BLUE_GPIO_PIN);
	}
}

void lzport_gpio_set_all_leds(bool state)
{
	if (state) {
		GPIO_PortClear(GPIO, BOARD_LED_BLUE_GPIO_PORT, 1u << BOARD_LED_BLUE_GPIO_PIN);
		GPIO_PortClear(GPIO, BOARD_LED_GREEN_GPIO_PORT, 1u << BOARD_LED_GREEN_GPIO_PIN);
		GPIO_PortClear(GPIO, BOARD_LED_RED_GPIO_PORT, 1u << BOARD_LED_RED_GPIO_PIN);
	} else {
		GPIO_PortSet(GPIO, BOARD_LED_BLUE_GPIO_PORT, 1u << BOARD_LED_BLUE_GPIO_PIN);
		GPIO_PortSet(GPIO, BOARD_LED_GREEN_GPIO_PORT, 1u << BOARD_LED_GREEN_GPIO_PIN);
		GPIO_PortSet(GPIO, BOARD_LED_RED_GPIO_PORT, 1u << BOARD_LED_RED_GPIO_PIN);
	}
}
