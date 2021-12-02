#!/bin/bash

MCUX_WORKSPACE_LOC_SET=0
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
    if [ $MCUX_WORKSPACE_LOC_SET -eq 1 ]; then
      echo "Usage: $0 [OPTIONS] <mcuxpresso-workspace-path>"
      exit
    fi
    MCUX_WORKSPACE_LOC=$arg
    MCUX_WORKSPACE_LOC_SET=1
    shift
    ;;
  esac
done

if [ -z $MCUX_WORKSPACE_LOC ]; then
	echo "Usage: $0 <mcuxpresso-workspace-path>"
	exit
fi

# Check if workspace directory exists
if [ ! -d "$MCUX_WORKSPACE_LOC" ]; then
  echo "The specified workspace directory $MCUX_WORKSPACE_LOC does not exist. Exit.."
  exit
fi

MCUX_FLASH_DIR0=/usr/local/mcuxpressoide/ide/binaries/Flash
MCUX_FLASH_DIR1=$WORKSPACE_LOC/.mcuxpressoide_packages_support/LPC55S69_support/Flash
MCUX_IDE_BIN=/usr/local/mcuxpressoide/ide/binaries
MCUX_TOOL_LOC=/usr/local/mcuxpressoide/ide/tools/bin

# Erase flash completely
if [ $REVISION -eq 1 ]
then
  $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 --flash-driver-reset SYSRESETREQ --bootromstall 0x0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
else
  $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 --bootromstall 0x50000040 -CoreIndex=0 --flash-driver= -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
fi
