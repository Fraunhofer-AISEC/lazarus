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

#ifndef LZ_TRUSTZONE_LZ_POWER_HANDLER_H_
#define LZ_TRUSTZONE_LZ_POWER_HANDLER_H_

void lz_power_enter_sleep_nse(void);

void lz_power_init_rng_ring_oscillator_nse(void);

void lz_power_deinit_rng_ring_oscillator_nse(void);

bool lz_power_is_ring_oscillator_enabled_nse(void);

#endif /* LZ_TRUSTZONE_LZ_POWER_HANDLER_H_ */
