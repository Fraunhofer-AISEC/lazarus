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

INCLUDE "../../lz_common/linker_scripts/linker_script_memory.ld"

GROUP (
  "libgcc.a"
  "libc_nano.a"
  "libm.a"
  "libcr_newlib_nohost.a"
)

MEMORY
{
  DICEPP_CODE (rx) : ORIGIN = _LZ_DICEPP_CODE_START, LENGTH = _LZ_DICEPP_CODE_SIZE
  DICEPP_DATA (rx) : ORIGIN = _LZ_DICEPP_DATA_START, LENGTH = _LZ_DICEPP_DATA_SIZE
  LZ_CORE_HDR (rx) : ORIGIN = _LZ_CORE_HEADER_START, LENGTH = _LZ_CORE_HEADER_SIZE
  LZ_CORE_CODE (rx) : ORIGIN = _LZ_CORE_CODE_START, LENGTH = _LZ_CORE_CODE_SIZE
  SRAM (rwx) : ORIGIN = _LZ_SRAM_SECURE_START, LENGTH = _LZ_SRAM_SECURE_SIZE
  SRAM2 (rwx) : ORIGIN = _LZ_SRAM_PARAMS_START, LENGTH = _LZ_SRAM_PARAMS_SIZE
}

  __base_DICEPP_CODE = _LZ_DICEPP_CODE_START  ;
  __base_Flash = _LZ_DICEPP_CODE_START ;
  __top_DICEPP_CODE = _LZ_DICEPP_CODE_START + _LZ_DICEPP_CODE_SIZE ;
  __top_Flash = _LZ_DICEPP_CODE_START + _LZ_DICEPP_CODE_SIZE ;
  __base_DICEPP_DATA = _LZ_DICEPP_DATA_START  ;
  __base_Flash3 = _LZ_DICEPP_DATA_START ;
  __top_DICEPP_DATA = _LZ_DICEPP_DATA_START + _LZ_DICEPP_DATA_SIZE ;
  __top_Flash3 = _LZ_DICEPP_DATA_START + _LZ_DICEPP_DATA_SIZE ;
  __base_LZ_CORE_HDR = _LZ_CORE_HEADER_START  ;
  __base_Flash4 = _LZ_CORE_HEADER_START ;
  __top_LZ_CORE_HDR = _LZ_CORE_HEADER_START + _LZ_CORE_HEADER_SIZE ;
  __top_Flash4 = _LZ_CORE_HEADER_START + _LZ_CORE_HEADER_SIZE ;
  __base_LZ_CORE_CODE = _LZ_CORE_CODE_START  ;
  __base_Flash5 = _LZ_CORE_CODE_START ;
  __top_LZ_CORE_CODE = _LZ_CORE_CODE_START + _LZ_CORE_CODE_SIZE ;
  __top_Flash5 = _LZ_CORE_CODE_START + _LZ_CORE_CODE_SIZE ;
  __base_SRAM = _LZ_SRAM_SECURE_START  ;
  __base_RAM = _LZ_SRAM_SECURE_START ;
  __top_SRAM = _LZ_SRAM_SECURE_START + _LZ_SRAM_SECURE_SIZE ;
  __top_RAM = _LZ_SRAM_SECURE_START + _LZ_SRAM_SECURE_SIZE ;


ENTRY(ResetISR)

SECTIONS
{
    .dicepp_data (NOLOAD):
	{
    	. = ALIGN(4);
    	*(.DICEPP_DATA*)
    	. = ALIGN(4);
	} >DICEPP_DATA

	.lz_core_hdr (NOLOAD):
	{
    	. = ALIGN(4);
    	*(.LZ_CORE_HDR)
    	. = ALIGN(4);
	} >LZ_CORE_HDR

	.lz_core_code (NOLOAD):
	{
    	. = ALIGN(4);
    	*(.LZ_CORE_CODE)
    	. = ALIGN(4);
	} >LZ_CORE_CODE

    .text : ALIGN(4)
    {
        FILL(0xff)
        __vectors_start__ = ABSOLUTE(.) ;
        KEEP(*(.isr_vector))
        /* Global Section Table */
        . = ALIGN(4) ;
        __section_table_start = .;
        __data_section_table = .;
        LONG(LOADADDR(.data));
        LONG(    ADDR(.data));
        LONG(  SIZEOF(.data));
        __data_section_table_end = .;
        __bss_section_table = .;
        LONG(    ADDR(.bss));
        LONG(  SIZEOF(.bss));
        __bss_section_table_end = .;
        __section_table_end = . ;
        /* End of Global Section Table */

        *(.after_vectors*)

    } > DICEPP_CODE

    .text : ALIGN(4)
    {
       *(.text*)
       *(.rodata .rodata.* .constdata .constdata.*)
       . = ALIGN(4);
    } > DICEPP_CODE
    .ARM.extab : ALIGN(4)
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > DICEPP_CODE

    __exidx_start = .;

    .ARM.exidx : ALIGN(4)
    {
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > DICEPP_CODE
    __exidx_end = .;


    _etext = .;

    .uninit_RESERVED (NOLOAD) :
    {
        . = ALIGN(4) ;
        KEEP(*(.bss.$RESERVED*))
       . = ALIGN(4) ;
        _end_uninit_RESERVED = .;
    } > SRAM

    .data : ALIGN(4)
    {
       FILL(0xff)
       _data = . ;
       *(vtable)
       *(.ramfunc*)
       *(.data*)
       . = ALIGN(4) ;
       _edata = . ;
    } > SRAM AT>DICEPP_CODE

    .bss :
    {
        . = ALIGN(4) ;
        _bss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4) ;
        _ebss = .;
        PROVIDE(end = .);
    } > SRAM

    .noinit (NOLOAD):
    {
         . = ALIGN(4) ;
        _noinit = .;
        *(.noinit*)
         . = ALIGN(4) ;
        _end_noinit = .;
    } > SRAM

    _HeapSize = 0x1000;
    .heap :  ALIGN(4)
    {
        _pvHeapStart = .;
        . += _HeapSize;
        . = ALIGN(4);
        _pvHeapLimit = .;
    } > SRAM

     _StackSize = 0x1000;
    .heap2stackfill  :
    {
        . += _StackSize;
    } > SRAM
    .stack ORIGIN(SRAM) + LENGTH(SRAM) - _StackSize - 0:  ALIGN(4)
    {
        _vStackBase = .;
        . = ALIGN(4);
        _vStackTop = . + _StackSize;
    } > SRAM

	.ram_data (NOLOAD):
	{
		. = ALIGN(4);
		*(.RAM_DATA*)
		*(.RAM_DATA.Alias)
		*(.RAM_DATA.Certs)
		. = ALIGN(4);
	} > SRAM2

    PROVIDE(__valid_user_code_checksum = 0 -
                                         (_vStackTop
                                         + (ResetISR + 1)
                                         + (NMI_Handler + 1)
                                         + (HardFault_Handler + 1)
                                         + (( DEFINED(MemManage_Handler) ? MemManage_Handler : 0 ) + 1)
                                         + (( DEFINED(BusFault_Handler) ? BusFault_Handler : 0 ) + 1)
                                         + (( DEFINED(UsageFault_Handler) ? UsageFault_Handler : 0 ) + 1)
                                         ) );

    _image_start = LOADADDR(.text);
    _image_end = LOADADDR(.data) + SIZEOF(.data);
    _image_size = _image_end - _image_start;
}