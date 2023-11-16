#include "lz_config.h"
#include "lz_common.h"
#include "lzport_flash.h"
#include "lzport_memory.h"
#include "lzport_debug_output.h"
#include "lzport_throttle_timer.h"
#include "board_init.h"
#include "lz_core.h"
#include "lz_update.h"
#include "lz_awdt.h"
#include "lzport_gpio.h"

int main(void)
{
	lzport_core_board_init();

	lzport_gpio_rts_init();
	lzport_gpio_set_rts(false);

	lzport_init_debug();
	if (!lzport_flash_init()) {
		ERROR("Failed to initialize flash\n");
		lz_error_handler();
	}
	lz_print_img_info("Lazarus Core", &lz_core_hdr);
	lzport_throttle_timer_init();
	lzport_rng_init();

	boot_mode_t boot_mode = lz_core_run();

	switch_to_next_layer(boot_mode);

	return 0;
}