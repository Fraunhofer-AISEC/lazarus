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

#ifndef LZ_AWDT_H_
#define LZ_AWDT_H_

//
// Note: AWDT handler functions (NSE entry points) are located in lz_common/lz_trustzone_handler/
//

LZ_RESULT lz_awdt_init(uint32_t time_s);
bool lz_awdt_last_reset_awdt(void);

#endif /* LZ_AWDT_H_ */
