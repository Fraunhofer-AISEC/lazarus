// Copyright(c) 2022 Fraunhofer AISEC

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "FreeRTOS.h"
#include "task.h"

#include "lz_common.h"
#include "lz_error.h"
#include "lz_query_version_handler.h"
#include "lzport_debug_output.h"
#include "net.h"
#include "lzport_gpio.h"

#define WAIT_BETWEEN_CHECKS_MS 10000

struct update_info {
	hdr_type_t type;
	const char *name;
	bool must_start_cpatcher;
};

static struct update_info update_infos[] = {
	/*
	 *  type                  name       start_cpatcher
	 *   |                     |              |
	 *   V                     V              V         */
	{ APP_UPDATE, "App", false },
	{ LZ_CORE_UPDATE, "Core", true },
	{ LZ_CPATCHER_UPDATE, "Cpatcher", false },
	{ LZ_UDOWNLOADER_UPDATE, "Udownloader", false },
};

static void reboot_device(const struct update_info *update_info)
{
	if (update_info->must_start_cpatcher) {
		if (lz_set_boot_mode_request(LZ_CPATCHER) != LZ_SUCCESS) {
			WARN("(UPDATE) Failed to set boot mode request\n");
		}
	}
	INFO("(UPDATE) Requesting reboot to apply update\n");
	net_close_reboot();
}

static void download_and_install_update(const struct update_info *update_info)
{
	if (net_fw_update(update_info->type) == LZ_SUCCESS) {
		reboot_device(update_info);
	} else {
		INFO("(UPDATE) Failed to download update from hub\n");
	}
}

static LZ_RESULT get_current_version(const struct update_info *update_info,
									 uint32_t *current_version)
{
	struct lz_query_version_info version_info;
	if (lz_query_version_nse(update_info->type, &version_info) != LZ_SUCCESS) {
		ERROR("(UPDATE) Failed to query version for %s\n", update_info->name);
		return LZ_ERROR;
	}

	*current_version = version_info.version;
	return LZ_SUCCESS;
}

static LZ_RESULT version_from_string(const char *str, uint32_t *version)
{
	unsigned major, minor;
	if (sscanf(str, "%u.%u", &major, &minor) != 2) {
		ERROR("(UPDATE) Version string has an invalid format\n");
		return LZ_ERROR;
	}

	*version = major << 16 | minor;
	return LZ_SUCCESS;
}

static void perform_update(const struct update_info *update_info,
						   const struct lz_net_version_info *version_info)
{
	uint32_t current_version;
	if (get_current_version(update_info, &current_version) != LZ_SUCCESS)
		return;

	uint32_t newest_version;
	if (version_from_string(version_info->newest_version, &newest_version) != LZ_SUCCESS)
		return;

	if (current_version < newest_version) {
		INFO("(UPDATE) New version for %s available (version=%s)\n", version_info->name,
			 version_info->newest_version);

		download_and_install_update(update_info);
	} else {
		INFO("(UPDATE) %s: No update required (version=%s)\n", update_info->name,
			 version_info->newest_version);
	}
}

static void perform_updates(unsigned num_updates,
							const struct lz_net_check_for_update_result *version_infos)
{
	for (int i = 0; i < num_updates; i++)
		perform_update(&update_infos[i], &version_infos->components[i]);
}

void check_for_updates(void)
{
	INFO("(UPDATE) Checking for updates..\n");

	size_t num_updates = sizeof(update_infos) / sizeof(update_infos[0]);
	hdr_type_t types[num_updates];
	for (int i = 0; i < num_updates; i++)
		types[i] = update_infos[i].type;

	struct lz_net_check_for_update_result version_infos;
	LZ_RESULT result = net_check_for_update(types, num_updates, &version_infos);
	if (result != LZ_SUCCESS) {
		INFO("ERROR: (UPDATE) Failed to check for update\n");
		return;
	}

	perform_updates(num_updates, &version_infos);
}

void lz_update_task(void *params)
{
	// Wait until network connection is established
	ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(portMAX_DELAY));

	// Delay for half of the interval to check for updates between the AWDT
	// triggers. This will make the logging output less interlaced (and noisy).
	vTaskDelay(pdMS_TO_TICKS(WAIT_BETWEEN_CHECKS_MS / 2));

	// Periodically fetch new deferral tickets to avoid a system reset
	for (;;) {
		check_for_updates();

		INFO("(UPDATE) Waiting for %dms\n", WAIT_BETWEEN_CHECKS_MS);
		vTaskDelay(pdMS_TO_TICKS(WAIT_BETWEEN_CHECKS_MS));
	}
}
