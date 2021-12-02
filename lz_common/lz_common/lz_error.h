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

#ifndef LZ_COMMON_LZ_ERROR_H_
#define LZ_COMMON_LZ_ERROR_H_

/*******************************************
 * Error Handling
 *******************************************/
typedef uint32_t LZ_RESULT;

#define LZ_SUCCESS 0x00000000

#define LZ_ERROR 0xFFFFFFFF
#define LZ_ERROR_ACCESS_DENIED 0xFFFFFFFE
#define LZ_ERROR_BAD_FORMAT 0xFFFFFFFD
#define LZ_ERROR_INVALID_HDR 0xFFFFFFFC
#define LZ_TIMEOUT 0xFFFFFFFB
#define LZ_ERROR_ESP_ERROR 0xFFFFFFFA
#define LZ_ERROR_ESP_BUSY 0xFFFFFFF9
#define LZ_ERROR_ESP_ALREADY_CONN 0xFFFFFFF8
#define LZ_ERROR_NETWORK 0xFFFFFFF7

#define LZ_NOT_FOUND 0xFFFFFF0F

#endif /* LZ_COMMON_LZ_ERROR_H_ */
