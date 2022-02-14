#include <stdint.h>
#include "lz_config.h"
#include "lz_common.h"
#include "lz_error.h"
#include "lzport_flash.h"
#include "lzport_debug_output.h"
#include "lzport_dice.h"
#include "board_init.h"
#include "dicepp.h"

int main(void)
{
	lzport_dicepp_board_init();

	lzport_init_debug();
	lz_print_img_info("Lazarus DICE++", NULL);
	lzport_flash_init();

	dicepp_run();

	lzport_init_tee();

	lzport_dicepp_switch_to_lz_core();

	// Should never be reached
	return -1;
}
