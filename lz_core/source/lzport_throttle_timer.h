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

#ifndef LZPORT_LPC55S69_LZPORT_THROTTLE_TIMER_H_
#define LZPORT_LPC55S69_LZPORT_THROTTLE_TIMER_H_

#include "stdint.h"
#include <stdbool.h>

void lzport_throttle_timer_init();
void lzport_throttle_timer_start();
bool lzport_throttle_timer_is_active();

#endif
