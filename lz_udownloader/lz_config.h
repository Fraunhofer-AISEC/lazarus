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

#ifndef LZ_CONFIG_H
#define LZ_CONFIG_H

// Do not edit! These are just the debug output levels
#define DBG_NONE (0x0U)
#define DBG_ERR (0x1U)
#define DBG_WARN (0x2U)
#define DBG_INFO (0x4U)
#define DBG_VERB (0x8U)

// Set the desired debug output here (The definitions from above can be OR'ed)
#define LZ_DBG_LEVEL (DBG_ERR | DBG_WARN | DBG_INFO)

#endif /* LZ_CONFIG_H */
