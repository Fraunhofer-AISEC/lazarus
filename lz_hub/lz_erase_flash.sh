#!/bin/bash

REVISION=2

for arg in "$@"
do
  case $arg in
  -r1|--revision1)
    REVISION=1
    shift
    ;;
  -r2|--revision2)
    REVISION=2
    shift
    ;;
  *)
      echo "Usage: $0 [-r1 | -r2]"
      exit
      shift
      ;;
  esac
done

MCUX_FLASH_DIR=/usr/local/mcuxpressoide/ide/binaries/Flash
MCUX_IDE_BIN=/usr/local/mcuxpressoide/ide/binaries
MCUX_TOOL_LOC=/usr/local/mcuxpressoide/ide/tools/bin
LAZARUS_LOC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"

# Erase flash completely
if [ $REVISION -eq 1 ]
then
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 --flash-driver-reset SOFT $BOOTROMSTALL -x $LAZARUS_LOC/lz_hub/lpc55s69-flash/binaries --flash-dir $MCUX_FLASH_DIR
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 --flash-driver-reset SOFT --bootromstall 0x50000040 -CoreIndex=0 --flash-driver= -x $LAZARUS_LOC/lz_hub/lpc55s69-flash/binaries --flash-dir $MCUX_FLASH_DIR --PreconnectScript LS_preconnect_LPC55xx.scp --flash-hashing
fi
