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

#include "lzport_debug_output/lzport_debug_output.h"
#include "lz_config.h"

#if (LZ_DBG_LEVEL > 0)

void dbgprint_data(uint8_t *data, uint32_t len, char *info)
{
	if (info) {
		dbgprint(DBG_INFO, "INFO: %s:\n0x", info);
	}
	for (uint32_t i = 0; i < len; i++) {
		if (((i + 1) % 30) == 0) {
			dbgprint(DBG_INFO, "\n");
		}
		dbgprint(DBG_INFO, "%02x", data[i]);
	}
	dbgprint(DBG_INFO, "\n");
}

#endif
