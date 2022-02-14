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

#ifndef LZ_TASK_AWDT_H_
#define LZ_TASK_AWDT_H_

#define DEFERRAL_TICKET_TIME_MS 60000
#define DEFERRAL_TICKET_TASK_WAIT_MS 30000
#define DEFERRAL_TICKET_FETCHING_MULT 10

void lz_awdt_task(void *params);
TaskHandle_t get_task_awdt_handle(void);

#endif /* LZ_TASK_AWDT_H_ */
