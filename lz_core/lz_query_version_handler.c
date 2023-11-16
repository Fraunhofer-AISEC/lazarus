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

#include "arm_cmse.h"
#include "lz_query_version_handler.h"
#include "lzport_debug_output.h"
#include "lz_common.h"

struct update_info {
	hdr_type_t type;
	volatile lz_img_hdr_t *header;
};

static struct update_info update_infos[] = {
	{ APP_UPDATE, &lz_app_hdr },
	{ LZ_CORE_UPDATE, &lz_core_hdr },
	{ LZ_CPATCHER_UPDATE, &lz_cpatcher_hdr },
	{ LZ_UDOWNLOADER_UPDATE, &lz_udownloader_hdr },
};

__attribute__((cmse_nonsecure_entry)) LZ_RESULT
lz_query_version_nse(hdr_type_t type, struct lz_query_version_info *version_info)
{
	VERB("DEBUG: NSE Entry Point: Query version..\n");

	for (int i = 0; i < sizeof(update_infos) / sizeof(update_infos[0]); i++) {
		if (update_infos[i].type == type) {
			// Found entry for requested type
			volatile lz_img_hdr_t *header = update_infos[i].header;
			version_info->version = header->hdr.content.version;
			return LZ_SUCCESS;
		}
	}

	// Did not find matching entry for requested type found
	return LZ_ERROR;
}
