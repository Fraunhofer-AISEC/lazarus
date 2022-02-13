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

INCLUDE "../lz_common/linker_scripts/linker_script_memory.ld"

 GROUP (
  "libgcc.a"
  "libc_nano.a"
  "libm.a"
  "libcr_newlib_nohost.a"
)

MEMORY
{
  UD_HDR (rx) : ORIGIN = _LZ_UDOWNLOADER_HEADER_START, LENGTH = _LZ_UDOWNLOADER_HEADER_SIZE
  UD_CODE (rx) : ORIGIN = _LZ_UDOWNLOADER_CODE_START, LENGTH = _LZ_UDOWNLOADER_CODE_SIZE /* 62K bytes (alias Flash) */
  APP_HDR (rx) : ORIGIN = _APP_HEADER_START, LENGTH = _APP_HEADER_SIZE /* 2K bytes (alias Flash2) */
  APP_CODE (rx) : ORIGIN = _APP_CODE_START, LENGTH = 0x27800 /* 158K bytes (alias Flash3) */
  LZ_DATA_STORE (rx) : ORIGIN = _LZ_DATA_STORAGE_START, LENGTH = _LZ_DATA_STORAGE_SIZE /* 8K bytes (alias Flash4) */
  STAGING_AREA (rx) : ORIGIN = _LZ_STAGING_AREA_START, LENGTH = _LZ_STAGING_AREA_SIZE /* 160K bytes (alias Flash5) */
  SRAM (rwx) : ORIGIN = _LZ_SRAM_NON_SECURE_START, LENGTH = _LZ_SRAM_NON_SECURE_SIZE /* 216K bytes (alias RAM) */
  SRAM2 (rwx) : ORIGIN = _LZ_SRAM_PARAMS_START, LENGTH = _LZ_SRAM_PARAMS_SIZE
}

ENTRY(ResetISR)

SECTIONS
{
    .ud_hdr (NOLOAD):
    {
    	. = ALIGN(4);
    	KEEP (*(.UD_HDR))
    	*(.UD_HDR*)
    	. = ALIGN(4);
    } > UD_HDR

	.app_hdr (NOLOAD):
	{
	  . = ALIGN(4);
	  KEEP (*(.APP_HDR))
	  *(.APP_HDR*)
	  . = ALIGN(4);
	} >APP_HDR

	.app_code (NOLOAD):
	{
	  . = ALIGN(4);
	  KEEP (*(.APP_CODE))
	  *(.APP_CODE*)
	  . = ALIGN(4);
	} >APP_CODE

	.lz_data_store (NOLOAD):
	{
	  . = ALIGN(4);
	  KEEP (*(.LZ_DATA_STORE))
	  *(.LZ_DATA_STORE*)
	  . = ALIGN(4);
	} >LZ_DATA_STORE

	.staging_area (NOLOAD):
	{
		. = ALIGN(4);
		KEEP (*(.STAGING_AREA))
		*(.STAGING_AREA)
		. = ALIGN(4);
	} > STAGING_AREA

    /* MAIN TEXT SECTION */
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

    } > UD_CODE

    .text : ALIGN(4)
    {
       *(.text*)
       *(.rodata .rodata.* .constdata .constdata.*)
       . = ALIGN(4);
    } > UD_CODE
    /*
     * for exception handling/unwind - some Newlib functions (in common
     * with C++ and STDC++) use this.
     */
    .ARM.extab : ALIGN(4)
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > UD_CODE

    __exidx_start = .;

    .ARM.exidx : ALIGN(4)
    {
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > UD_CODE
    __exidx_end = .;

    _etext = .;

    /* MAIN DATA SECTION */
    .uninit_RESERVED (NOLOAD) :
    {
        . = ALIGN(4) ;
        KEEP(*(.bss.$RESERVED*))
       . = ALIGN(4) ;
        _end_uninit_RESERVED = .;
    } > SRAM

    /* Main DATA section (SRAM) */
    .data : ALIGN(4)
    {
       FILL(0xff)
       _data = . ;
       *(vtable)
       *(.ramfunc*)
       *(.data*)
       . = ALIGN(4) ;
       _edata = . ;
    } > SRAM AT>UD_CODE

    /* MAIN BSS SECTION */
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

    /* DEFAULT NOINIT SECTION */
    .noinit (NOLOAD):
    {
         . = ALIGN(4) ;
        _noinit = .;
        *(.noinit*)
         . = ALIGN(4) ;
        _end_noinit = .;
    } > SRAM

    /* Reserve and place Heap within memory map */
    _HeapSize = _HEAP_SIZE_LZ_UDOWNLOADER;
    .heap :  ALIGN(4)
    {
        _pvHeapStart = .;
        . += _HeapSize;
        . = ALIGN(4);
        _pvHeapLimit = .;
    } > SRAM

     _StackSize = _STACK_SIZE_LZ_UDOWNLOADER;
     /* Reserve space in memory for Stack */
    .heap2stackfill  :
    {
        . += _StackSize;
    } > SRAM
    /* Locate actual Stack in memory map */
    .stack ORIGIN(SRAM) + LENGTH(SRAM) - _StackSize - 0:  ALIGN(4)
    {
        _vStackBase = .;
        . = ALIGN(4);
        _vStackTop = . + _StackSize;
    } > SRAM

    .fill :
    {
        FILL(0xFF)
        . = ORIGIN(UD_CODE) + LENGTH(UD_CODE) - 1;
        BYTE(0xFF); /* Needed as the linker needs to have something in the output section */
    } > UD_CODE

	/* Parameters provided via RAM  */
	.ram_data (NOLOAD):
	{
	  . = ALIGN(4);
	  *(.RAM_DATA*)
	  *(.RAM_DATA.Alias)
	  *(.RAM_DATA.Certs)
	  . = ALIGN(4);
	} >SRAM2

    /* ## Create checksum value (used in startup) ## */
    PROVIDE(__valid_user_code_checksum = 0 -
                                         (_vStackTop
                                         + (ResetISR + 1)
                                         + (NMI_Handler + 1)
                                         + (HardFault_Handler + 1)
                                         + (( DEFINED(MemManage_Handler) ? MemManage_Handler : 0 ) + 1)   /* MemManage_Handler may not be defined */
                                         + (( DEFINED(BusFault_Handler) ? BusFault_Handler : 0 ) + 1)     /* BusFault_Handler may not be defined */
                                         + (( DEFINED(UsageFault_Handler) ? UsageFault_Handler : 0 ) + 1) /* UsageFault_Handler may not be defined */
                                         ) );

    /* Provide basic symbols giving location and size of main text
     * block, including initial values of RW data sections. Note that
     * these will need extending to give a complete picture with
     * complex images (e.g multiple Flash banks).
     */
    _image_start = LOADADDR(.text);
    _image_end = LOADADDR(.data) + SIZEOF(.data);
    _image_size = _image_end - _image_start;
}