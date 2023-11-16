// Copyright(c) 2022 Fraunhofer AISEC

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "queue.h"
#include "semphr.h"
#include "task.h"

#include "lz_config.h"
#include "lz_error.h"
#include "lzport_memory.h"
#include "lzport_debug_output.h"
#include "lzport_gpio.h"
#include "lz_common.h"
#include "lz_net.h"
#include "lz_awdt.h"

#define QUEUE_NUM_ELEMENTS 10

struct reassoc_data {
	uint8_t *dev_uuid;
	uint8_t *dev_auth;
	uint8_t *device_id_csr;
	uint32_t device_id_csr_size;
};

struct check_for_update_data {
	hdr_type_t update_types[LZ_NET_MAX_COMPONENTS];
	unsigned num_update_types;
	struct lz_net_check_for_update_result *result;
};

struct queue_item {
	enum item_type {
		ITEM_TYPE_SENSOR_DATA,
		ITEM_TYPE_ALIAS_ID,
		ITEM_TYPE_BOOT_TICKET,
		ITEM_TYPE_AWDT,
		ITEM_TYPE_REASSOC,
		ITEM_TYPE_FW_UPDATE,
		ITEM_TYPE_CHECK_FOR_UPDATE,
		ITEM_TYPE_NET_CLOSE_REBOOT,
		ITEM_TYPE_USER_INPUT,
	} type;

	union {
		struct lz_net_sensor_data sensor_data;
		uint32_t awdt_req_time_ms;
		struct reassoc_data reassoc_data;
		hdr_type_t fw_update_type;
		struct check_for_update_data check_for_update;
	} payload;

	TaskHandle_t calling_task;
	LZ_RESULT result;
};

static TaskHandle_t net_task_handle = NULL;
static QueueHandle_t net_queue;

static LZ_RESULT enqueue_item(struct queue_item *item)
{
	item->calling_task = xTaskGetCurrentTaskHandle();

	if (xQueueSend(net_queue, &item, (TickType_t)0) != pdPASS) {
		ERROR("Failed to enqueue to network queue\n");
		return LZ_ERROR;
	}

	// wait until worker thread is done processing our item
	ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(portMAX_DELAY));

	LZ_RESULT result = item->result;
	if (result != LZ_SUCCESS) {
		ERROR("Result of network transaction failed: %x\n", result);
	}

	return result;
}

LZ_RESULT net_send_data(struct lz_net_sensor_data sensor_data)
{
	struct queue_item item = {};
	item.type = ITEM_TYPE_SENSOR_DATA;
	item.payload.sensor_data = sensor_data;
	return enqueue_item(&item);
}

LZ_RESULT net_send_alias_id_cert(void)
{
	struct queue_item item = {};
	item.type = ITEM_TYPE_ALIAS_ID;
	return enqueue_item(&item);
}

LZ_RESULT net_refresh_boot_ticket(void)
{
	struct queue_item item = {};
	item.type = ITEM_TYPE_BOOT_TICKET;
	return enqueue_item(&item);
}

LZ_RESULT net_refresh_awdt(uint32_t requested_time_ms)
{
	struct queue_item item = {};
	item.type = ITEM_TYPE_AWDT;
	item.payload.awdt_req_time_ms = requested_time_ms;
	return enqueue_item(&item);
}

LZ_RESULT net_reassociate_device(uint8_t *dev_uuid, uint8_t *dev_auth, uint8_t *device_id_csr,
								 uint32_t device_id_csr_size)
{
	struct queue_item item = {};
	item.type = ITEM_TYPE_REASSOC;
	item.payload.reassoc_data.dev_uuid = dev_uuid;
	item.payload.reassoc_data.dev_auth = dev_auth;
	item.payload.reassoc_data.device_id_csr = device_id_csr;
	item.payload.reassoc_data.device_id_csr_size = device_id_csr_size;
	return enqueue_item(&item);
}

LZ_RESULT net_fw_update(hdr_type_t update_type)
{
	struct queue_item item = {};
	item.type = ITEM_TYPE_FW_UPDATE;
	item.payload.fw_update_type = update_type;
	return enqueue_item(&item);
}

LZ_RESULT net_check_for_update(hdr_type_t update_types[], unsigned num_update_types,
							   struct lz_net_check_for_update_result *result)
{
	struct queue_item item = {};
	item.type = ITEM_TYPE_CHECK_FOR_UPDATE;
	memcpy(item.payload.check_for_update.update_types, update_types,
		   num_update_types * sizeof(hdr_type_t));
	item.payload.check_for_update.num_update_types = num_update_types;
	item.payload.check_for_update.result = result;

	return enqueue_item(&item);
}

LZ_RESULT net_close_reboot(void)
{
	struct queue_item item = {};
	item.type = ITEM_TYPE_NET_CLOSE_REBOOT;
	return enqueue_item(&item);
}

LZ_RESULT net_request_user_input(void)
{
	struct queue_item item = {};
	item.type = ITEM_TYPE_USER_INPUT;
	return enqueue_item(&item);
}

static LZ_RESULT handle_queue(void)
{
	struct queue_item *item;
	LZ_RESULT result = LZ_ERROR;

	// wait until new work is available
	if (xQueueReceive(net_queue, &item, portMAX_DELAY) != pdPASS) {
		ERROR("Could not receive from network queue\n");
		return LZ_ERROR;
	}

	switch (item->type) {
	case ITEM_TYPE_SENSOR_DATA:
		result = lz_net_send_data(item->payload.sensor_data);
		break;
	case ITEM_TYPE_ALIAS_ID:
		result = lz_net_send_alias_id_cert();
		break;
	case ITEM_TYPE_BOOT_TICKET:
		result = lz_net_refresh_boot_ticket();
		break;
	case ITEM_TYPE_AWDT:
		result = lz_net_refresh_awdt(item->payload.awdt_req_time_ms);
		break;
	case ITEM_TYPE_REASSOC:
		result = lz_net_reassociate_device(item->payload.reassoc_data.dev_uuid,
										   item->payload.reassoc_data.dev_auth,
										   item->payload.reassoc_data.device_id_csr,
										   item->payload.reassoc_data.device_id_csr_size);
		break;
	case ITEM_TYPE_FW_UPDATE:
		result = lz_net_fw_update(item->payload.fw_update_type);
		break;
	case ITEM_TYPE_CHECK_FOR_UPDATE:
		result = lz_net_check_for_update(item->payload.check_for_update.update_types,
										 item->payload.check_for_update.num_update_types,
										 item->payload.check_for_update.result);
		break;
	case ITEM_TYPE_NET_CLOSE_REBOOT:
		result = lz_net_close_reboot();
		// Should never be reached
		break;
	case ITEM_TYPE_USER_INPUT:
		result = lz_net_request_user_input();
		break;
	default:
		ERROR("unknown network queue item type %x\n", item->type);
		break;
	}

	// wake up calling thread and notify that we're done with its item
	item->result = result;
	xTaskNotifyGive(item->calling_task);

	return result;
}

void net_task(void *params)
{
	bool first_connect = true;
	net_queue = xQueueCreate(QUEUE_NUM_ELEMENTS, sizeof(struct queue_item));
	if (!net_queue) {
		ERROR("Could not initialize network queue. Waiting forever..\n");
		for (;;)
			;
	}

	for (;;) {
		// Setup ESP8266, connect to Wi-Fi AP
		if (LZ_SUCCESS != lz_net_init()) {
			ERROR("Could not initialize network connection\n");
			continue;
		}

		// Open socket
		if (LZ_SUCCESS != lz_net_open()) {
			ERROR("ERROR Failed to open socket\n");
			continue;
		}

		// On first connect, send AliasID, boot ticket and wake up other tasks
		if (first_connect) {
			// Send AliasID certificate
			if (LZ_SUCCESS != lz_net_send_alias_id_cert()) {
				WARN("Updating AliasID cert in backend not successful\n");
				continue;
			}

			// Fetch boot ticket for next boot
			if (lz_net_refresh_boot_ticket() != LZ_SUCCESS) {
				WARN("Could not retrieve a boot ticket from backend.\n");
				continue;
			}

			// Notify all waiting tasks that network connection is established
			TaskHandle_t *wakeup_tasks = params;
			for (TaskHandle_t *i = wakeup_tasks; *i; i++)
				xTaskNotifyGive(*i);

			first_connect = false;
		}

		for (;;) {
			if (handle_queue() == LZ_ERROR_NET) {
				ERROR("Net Task: Wifi Error. Closing socket\n");
				break;
			}
		}

		// Close the socket and then re-initialize the connection
		lz_net_close();
	}
}

TaskHandle_t get_net_task_handle(void)
{
	return net_task_handle;
}
