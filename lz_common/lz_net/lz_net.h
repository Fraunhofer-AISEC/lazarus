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

/**
 * Initialize the network connection
 */
LZ_RESULT lz_net_init(void);

LZ_RESULT lz_net_send_data(uint8_t *data, uint32_t data_size);

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

LZ_RESULT lz_request_element(hdr_t *request_hdr, uint8_t *request_payload, hdr_t *response_hdr,
							 uint8_t *response_payload, uint32_t response_payload_size);

LZ_RESULT lz_request_auth_element(lz_auth_hdr_t *request_header, uint8_t *request_payload,
								  lz_auth_hdr_t *response_hdr, uint8_t *response_payload,
								  uint32_t reponse_payload_size);

#endif /* RE_NET_RE_NET_H_ */
