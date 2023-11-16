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

#ifndef LZ_QUERY_VERSION_HANDLER_H_
#define LZ_QUERY_VERSION_HANDLER_H_

#include <stdint.h>
#include "lz_common.h"
#include "lz_error.h"

struct lz_query_version_info {
	uint32_t version;
};

LZ_RESULT lz_query_version_nse(
		hdr_type_t type,
		struct lz_query_version_info *version_info);

#endif /* LZ_QUERY_VERSION_HANDLER_H_ */
