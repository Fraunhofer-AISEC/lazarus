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


/* Define constants for each memory region according to lzport_memory.h
 * If something is changed here, it has to be changed in lzport_memory.h as well!
 */
_LZ_DICEPP_CODE_START        	= 0x10000000;
_LZ_DICEPP_CODE_SIZE         	= 0x00008000;
_LZ_DICEPP_DATA_START        	= 0x10008000;
_LZ_DICEPP_DATA_SIZE         	= 0x00000800;

_LZ_CORE_HEADER_START        	= 0x10010000;
_LZ_CORE_HEADER_SIZE         	= 0x00000800;
_LZ_CORE_CODE_START          	= 0x10010800;
_LZ_CORE_CODE_SIZE           	= 0x0001B400;
_LZ_CORE_NSC_START           	= 0x1002BC00;
_LZ_CORE_NSC_SIZE            	= 0x00000400;

_LZ_CPATCHER_HEADER_START       = 0x1002C000;
_LZ_CPATCHER_HEADER_SIZE        = 0x00000800;
_LZ_CPATCHER_CODE_START         = 0x1002C800;
_LZ_CPATCHER_CODE_SIZE          = 0x0000F800;

_LZ_UDOWNLOADER_HEADER_START	= 0x0003C000;
_LZ_UDOWNLOADER_HEADER_SIZE     = 0x00000800;
_LZ_UDOWNLOADER_CODE_START      = 0x0003C800;
_LZ_UDOWNLOADER_CODE_SIZE       = 0x00013800;

_APP_HEADER_START         		= 0x00050000;
_APP_HEADER_SIZE          		= 0x00000800;
_APP_CODE_START           		= 0x00050800;
_APP_CODE_SIZE            		= 0x0001F400;
_APP_VULN_START                 = 0x0006FC00;
_APP_VULN_SIZE                  = 0x00000400;

_LZ_DATA_STORAGE_START       	= 0x00070000;
_LZ_DATA_STORAGE_SIZE        	= 0x00002000;

_LZ_STAGING_AREA_START       	= 0x00072000;
_LZ_STAGING_AREA_SIZE        	= 0x00028000;

_LZ_SRAM_SECURE_START        	= 0x30000000;
_LZ_SRAM_SECURE_SIZE         	= 0x00008000;
_LZ_SRAM_PARAMS_START 		 	= 0x20008000;
_LZ_SRAM_PARAMS_SIZE	     	= 0x00001800;
_LZ_SRAM_NON_SECURE_START	 	= 0x2000A000;
_LZ_SRAM_NON_SECURE_SIZE	 	= 0x00036000;

_HEAP_SIZE_LZ_DICEPP			= 0x4000;
_HEAP_SIZE_LZ_CORE				= 0x4000;
_HEAP_SIZE_LZ_CPATCHER			= 0x4000;
_HEAP_SIZE_LZ_UDOWNLOADER		= 0x4000;
_HEAP_SIZE_DEMO_APP				= 0x4000;

_STACK_SIZE_LZ_DICEPP			= 0x3000;
_STACK_SIZE_LZ_CORE				= 0x3000;
_STACK_SIZE_LZ_CPATCHER         = 0x3000;
_STACK_SIZE_LZ_UDOWNLOADER		= 0x3000;
_STACK_SIZE_DEMO_APP			= 0x3000;

