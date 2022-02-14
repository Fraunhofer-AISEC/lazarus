#include "lz_config.h"
#include "lz_common.h"
#include "lzport_debug_output.h"
#include "lzport_memory.h"
#include "lzport_usart.h"
#include "lzport_rng.h"
#include "lzport_gpio.h"
#include "lzport_systick_delay.h"
#include "lz_power_handler.h"
#include "lz_net.h"
#include "board_init.h"
#include "lz_udownloader.h"

int main(void)
{
	lzport_udownloader_init_board();

	lzport_init_debug();
	lz_print_img_info("Lazarus Update Downloader", &lz_udownloader_hdr);

	lzport_init_systick_1khz();
	lzport_usart_init_esp();
	lzport_gpio_rts_init();
	lzport_gpio_set_rts(false);
	lzport_rng_init();

	lz_udownloader_run();

	// Deinitialize peripherals
	lzport_deinit_systick();

	dbgprint(DBG_INFO, "INFO: UD functionality terminated. Rebooting..\n");

	NVIC_SystemReset();

	return 0;
}