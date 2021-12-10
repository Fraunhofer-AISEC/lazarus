lizard lz_dicepp/source lz_dicepp/include lz_dicepp/trustzone/ lz_common/lz_common/ lz_common/lz_port/lpc55s69/lzport_dice lz_common/lz_port/lpc55s69/lzport_flash lz_common/lz_port/lpc55s69/lzport_memory lz_common/lz_port/lpc55s69/lzport_rng lz_common/lz_port/lpc55s69/lzport_usart
echo " ------------------------------------ END DICEPP ----------------------------------------"
echo ""
echo ""

lizard lz_core/source lz_core/include lz_core/trustzone lz_common/lz_common lz_common/lz_port/lpc55s69/lzport_flash lz_common/lz_port/lpc55s69/lzport_memory lz_common/lz_port/lpc55s69/lzport_rng lz_common/lz_port/lpc55s69/lzport_wdt
echo "------------------------------------- END LZ_CORE ----------------------------------------"
echo ""
echo ""

lizard lz_cpatcher/source lz_cpatcher/include lz_common/lz_port/lpc55s69/lzport_flash lz_common/lz_port/lpc55s69/lzport_memory lz_common/lz_port/lpc55s69/lzport_rng
echo "------------------------------------ END LZ_CPATCHER -------------------------------------"
echo ""
echo ""

lizard lz_udownloader/source lz_udownloader/include lz_common/lz_common lz_common/lz_net lz_common/lzport/lzport_net lz_common/lz_port/lpc55s69/lzport_flash lz_common/lz_port/lpc55s69/lzport_memory lz_common/lz_port/lpc55s69/lzport_rng lz_common/lz_port/lpc55s69/lzport_usart
echo "------------------------------------ END LZ_UDOWNLOADER ----------------------------------"
echo ""
echo ""

lizard lz_common/mbedtls/
echo "------------------------------------- END CRYPTO LIB ------------------------------------"
echo ""
echo ""

lizard lz_core/CMSIS/
echo "-------------------------------------- END ARM CODE -------------------------------------"
echo ""
echo ""

lizard lz_core/board lz_core/device lz_core/drivers lz_core/startup -x"lz_core/board/boards/board.c" -x"lz_core/board/boards/board.h"
echo "-------------------------------------- END NXP CODE -------------------------------------"
echo ""
echo ""

