// Copyright(c) 2022 Fraunhofer AISEC

#ifndef NET_H_
#define NET_H_

#include <stdint.h>
#include "FreeRTOS.h"
#include "task.h"
#include "lz_common.h"
#include "lz_error.h"
#include "lz_net.h"

void net_task(void *params);
TaskHandle_t get_net_task_handle(void);

LZ_RESULT net_send_data(struct lz_net_sensor_data sensor_data);
LZ_RESULT net_send_alias_id_cert(void);
LZ_RESULT net_refresh_boot_ticket(void);
LZ_RESULT net_refresh_awdt(uint32_t requested_time_ms);
LZ_RESULT net_reassociate_device(uint8_t *dev_uuid,
								 uint8_t *dev_auth,
								 uint8_t *device_id_csr,
								 uint32_t device_id_csr_size);
LZ_RESULT net_fw_update(hdr_type_t update_type);
LZ_RESULT net_check_for_update(hdr_type_t update_types[],
							   unsigned num_update_types,
							   struct lz_net_check_for_update_result *result);
LZ_RESULT net_close_reboot(void);
LZ_RESULT net_request_user_input(void);

#endif /* NET_H_ */
