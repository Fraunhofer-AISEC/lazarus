#include "lz_config.h"
#include "lz_common.h"
#include "lzport_flash.h"
#include "lzport_debug_output.h"
#include "lz_cpatcher.h"
#include "board_init.h"

int main(void)
{
	lzport_cpatcher_init_board();

	lzport_init_debug();
	lzport_flash_init();
	lz_print_img_info("Lazarus Update Patcher", &lz_cpatcher_hdr);

	lz_core_patcher_run();

	return 0;
}