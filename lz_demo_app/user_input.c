// Copyright(c) 2023 Fraunhofer AISEC

#include "lz_config.h"
#include <stddef.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "lzport_debug_output.h"
#include "lz_flash_handler.h"
#include "fsl_debug_console.h"
#include "lzport_memory.h"
#include "net.h"
#include "user_input.h"

static TaskHandle_t *tasks;

typedef void (*func_t)();

typedef struct {
	uint32_t msecs;
	func_t func;
} interval_t;

static void suspend_tasks(void)
{
	VERB("Suspending tasks before accessing flash\n");

	TaskHandle_t current_task = xTaskGetCurrentTaskHandle();

	for (TaskHandle_t *i = tasks; *i; i++) {
		TaskHandle_t task = *i;
		if (task != current_task) {
			VERB("Suspend task %s\n", pcTaskGetName(task));
			vTaskSuspend(task);
		}
	}
}

uint32_t interval_msecs = 3000;

static void set_interval(uint32_t interval)
{
	INFO("RECEIVED INTERVAL %d (0x%x)\n", interval, interval);
	if (interval < 2000) {
		INFO("Interval %d ms too small. Must be at least %d ms\n", interval, 2000);
		return;
	} else if (interval > 10000) {
		INFO("Interval %d ms too large. Must be at most %d ms\n", interval, 10000);
		return;
	}

	interval_msecs = interval;
}

uint32_t get_interval(void)
{
	return interval_msecs;
}

__attribute__((section(".APP_VULN"))) static void erase_flash(uint32_t start)
{
	(void)start;
	INFO("FLASH WIPE FUNCTION\n");

	suspend_tasks();

	// Don't start to overwrite the application at the beginning. This contains
	// the vector table and may affect non-secure interrupts. Interrupts during
	// our secure call will result in weird behavior which may result in a crash
	// before our call completes.
	ptrdiff_t offset = 0x2000;
	uint8_t *cursor = (uint8_t *)LZ_APP_CODE_START + offset;
	uint8_t *end = (uint8_t *)(LZ_APP_CODE_START + LZ_APP_CODE_SIZE - offset);
	static uint8_t buf[0x200];
	memset(buf, 0, sizeof(buf));

	INFO("ERASING FLASH AREA\n");

	while (cursor < end) {
		if (!lz_flash_write_nse((void *)cursor, (void *)buf, sizeof(buf))) {
			ERROR("Failed to write to flash.\n");
			return;
		}
		cursor += sizeof(buf);

		// TODO:
		// Currently, when the app crashes and gets reset (by AWDT) inside the
		// fault handler, the program shows a weird behavior after reset.
		// Actually a reset should not carry any state from the time before the
		// reset. However, the lz_core binary can't access the memory region
		// that caused the fault. It is still unknown why this happens. After a
		// proper reset (using the reset button on the board), the problem is
		// gone.
		// As a workaround we will overwrite a single block in the flash, and
		// very likely the program will not crash. After that, we will wait
		// forever, and the AWDT reset happens outside of a fault handler.
		while (true)
			;
	}
	INFO("Done erasing flash area\n");
}

static void str_to_uint32(uint32_t *result, const char *str, size_t len)
{
	int i = 0;
	*result = 0;
	while (str[i] != '\0') {
		if (str[i] >= '0' && str[i] <= '9') {
			*result = *result * 10 + (str[i] - '0');
			i++;
		} else {
			ERROR("invalid input");
			return;
		}
	}
}

static void str_to_uint64(uint64_t *result, const char *str, size_t len)
{
	int i = 0;
	*result = 0;
	while (str[i] != '\0') {
		if (str[i] >= '0' && str[i] <= '9') {
			*result = *result * 10 + (str[i] - '0');
			i++;
		} else {
			ERROR("invalid input");
			return;
		}
	}
}

static void str_to_uint32_hex(uint32_t *result, const char *hex, size_t len)
{
	int i = 0;
	*result = 0;
	while (*hex && i < len) {
		char c = *hex++;
		*result <<= 4;
		if (c >= '0' && c <= '9') {
			*result += c - '0';
		} else if (c >= 'a' && c <= 'f') {
			*result += 10 + c - 'a';
		} else if (c >= 'A' && c <= 'F') {
			*result += 10 + c - 'A';
		}
		i++;
	}
}

static void str_to_uint64_hex(uint64_t *result, const char *hex, size_t len)
{
	int i = 0;
	*result = 0;
	while (*hex && i < len) {
		char c = *hex++;
		*result <<= 4;
		if (c >= '0' && c <= '9') {
			*result += c - '0';
		} else if (c >= 'a' && c <= 'f') {
			*result += 10 + c - 'a';
		} else if (c >= 'A' && c <= 'F') {
			*result += 10 + c - 'A';
		}
		i++;
	}
}

static void str_to_int(void *result, const char *hex, size_t len)
{
	bool is_hex = false;
	if (!strncmp(hex, "0x", 2)) {
		INFO("VERB: string is hex-formatted\n");
		hex += 2;
		len -= 2;
		is_hex = true;
	} else {
		INFO("VERB: string is decimal-formatted\n");
	}

	if (is_hex && len <= 8) {
		str_to_uint32_hex((uint32_t *)result, hex, len);
	} else if (is_hex && len <= 16) {
		str_to_uint64_hex((uint64_t *)result, hex, len);
	} else if (!is_hex && len <= 10) {
		str_to_uint32((uint32_t *)result, hex, len);
	} else if (!is_hex && len <= 20) {
		str_to_uint64((uint64_t *)result, hex, len);
	} else {
		ERROR("invalid length\n");
	}
}

static void debug_display_stack_info(func_t func, uint32_t *interval, uint32_t len)
{
	INFO("VERB: Received user input length %d\n", len);

	INFO("VERB: Interval @0x%x\n", interval);
	INFO("VERB: Func Ptr @0x%x\n", &func);

	INFO("VERB: set_interval @0x%x\n", &set_interval);
	INFO("VERB: erase_flash  @0x%x\n", &erase_flash);

	hexdump((uint8_t *)interval, 32, "VERB: @interval");
}

void process_user_input(uint8_t *data, uint32_t len, bool available)
{
	interval_t interval = { .msecs = 0xffffffff, .func = set_interval };

	if (available) {
		debug_display_stack_info(interval.func, &interval.msecs, len);

		str_to_int(&interval.msecs, (char *)data, len);

		debug_display_stack_info(interval.func, &interval.msecs, len);

		interval.func(interval);

	} else {
		INFO("No new user input\n");
		return;
	}
}

void user_input_task(void *params)
{
	tasks = params;

	// Wait until network connection is established
	ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(portMAX_DELAY));

	for (;;) {
		// read_command();

		INFO("Requesting user input..\n");

		net_request_user_input();

		vTaskDelay(pdMS_TO_TICKS(1000));
	}
}
