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

#ifndef LZ_NET_LZ_NET_H_
#define LZ_NET_LZ_NET_H_

#include <stdint.h>
#include <time.h>
#include "lz_common.h"

#define LZ_NET_MAX_COMPONENTS 8

typedef struct lz_net_sensor_data {
	uint32_t index;
	float temperature;
	float humidity;
} lz_net_sensor_data_t;

/**
 * Initialize the network connection
 */
LZ_RESULT lz_net_init(void);

LZ_RESULT lz_net_open(void);

LZ_RESULT lz_net_close(void);

LZ_RESULT lz_net_close_reboot(void);

LZ_RESULT lz_net_send_data(struct lz_net_sensor_data sensor_data);

/**
 * Send the alias id certificate to the backend
 */
LZ_RESULT lz_net_send_alias_id_cert(void);

/**
 * @return True if successful, otherwise false
 */
LZ_RESULT lz_net_refresh_boot_ticket(void);

/**
 * @param requested_time_ms the requested deferral time for the AWDT (the backend might override
 * this)
 * @return True if successful, otherwise false
 */
LZ_RESULT lz_net_refresh_awdt(uint32_t requested_time_ms);

/**
 * Performs the Lazarus device reassociation protocol after a Lazarus Core update. The device
 * reassociates its new DeviceID through attesting to the server with dev_uuid, dev_auth
 * and a new DeviceID CSR
 * @param dev_uuid The UUID of the device
 * @param dev_auth The dev_auth of the device
 * @param device_id_csr The new DeviceID Certificate Signing Request
 * @return LZ_SUCCESS on success, otherwise an error code
 */
LZ_RESULT lz_net_reassociate_device(uint8_t *dev_uuid, uint8_t *dev_auth, uint8_t *device_id_csr,
									uint32_t device_id_csr_size);

/**
 * Firmware update
 *
 * @param update_type App, UpdateDownloader, UpdatePatcher or Lazarus Core Update, see
 * hdr_type_t
 * @return LZ_SUCCESS on success, otherwise an error code
 */
LZ_RESULT lz_net_fw_update(hdr_type_t update_type);

struct lz_net_version_info {
	char name[20];
	char newest_version[10];
	time_t issue_time;
};

struct lz_net_check_for_update_result {
	struct lz_net_version_info components[LZ_NET_MAX_COMPONENTS];
};

LZ_RESULT lz_net_check_for_update(hdr_type_t update_types[],
								  unsigned num_update_types,
								  struct lz_net_check_for_update_result *result);

LZ_RESULT lz_net_request_user_input(void);

#endif /* RE_NET_RE_NET_H_ */
