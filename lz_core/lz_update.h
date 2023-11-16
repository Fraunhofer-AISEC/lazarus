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

#ifndef LZ_UPDATE_H_
#define LZ_UPDATE_H_

LZ_RESULT lz_apply_updates(const uint8_t expected_nonce[LEN_NONCE]);
LZ_RESULT lz_update_img_meta_data(void);
LZ_RESULT lz_std_updates_pending(void);
LZ_RESULT lz_verified_core_update_pending(void);

#endif /* LZ_UPDATE_H_ */
