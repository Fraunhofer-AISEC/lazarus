#!/bin/bash

START_SERVER=0
REVISION=2
CPU_CORES=$(nproc)

for arg in "$@"
do
    case $arg in
    -c|--clean)
        CLEAN_PROJECTS=1
        shift
        ;;
	-s|--start-server)
        START_SERVER=1
        shift
        ;;
    -r1|--revision1)
        REVISION=1
        shift
        ;;
    -r2|--revision2)
        REVISION=2
        shift
        ;;
    esac
done

if [ $REVISION -eq 1 ]
then
    BOOTROMSTALL="--flash-driver-reset SYSRESETREQ --bootromstall 0x0"
else
    BOOTROMSTALL="--bootromstall 0x50000040"
fi

MCUX_FLASH_DIR=/usr/local/mcuxpressoide/ide/binaries/Flash
MCUX_IDE_BIN=/usr/local/mcuxpressoide/ide/binaries
MCUX_TOOL_LOC=/usr/local/mcuxpressoide/ide/tools/bin
LAZARUS_LOC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"

# NOTE The non-secure application used for Lazarus can be set here. It must be a Makefile
# application (will be built with 'make -r -j$(nproc)'), otherwise further changes are required
APP_NAME=lz_demo_app # The name of the app
APP_DIR=$LAZARUS_LOC/$APP_NAME # The directory with the Makefile to build the app
APP_BIN=$APP_DIR/build/${APP_NAME}.bin # The binary to be flashed

APP_SIGNED_BIN=${APP_BIN%.*}_signed.bin # The signed binary, do not change

echo "Provisioning Lazarus with non-secure app $APP_NAME (binary: $APP_BIN, location: $APP_DIR).."

# Check if the workspace exists
if [ ! -d "$LAZARUS_LOC" ]; then
  echo "The workspace $LAZARUS_LOC does not exist. Exit"
  exit
fi

# Add tool location to PATH
export PATH=$MCUX_TOOL_LOC:$PATH

# Clean project if command line option -c | --clean was specified
if [ $CLEAN_PROJECTS -eq 1 ] ; then
    cd $APP_DIR
    make -r -j$CPU_CORES clean
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "$APP_NAME clean not successful. Exit.."
        exit
    fi
fi

cd $APP_DIR
make -r -j$CPU_CORES all
if [ $? -ne 0 ] ; then
    echo "$APP_NAME build not successful. Exit.."
	exit
fi

# kill all active debug processes
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*

# Load and sign the generated binaries and store them
cd $LAZARUS_LOC/lz_hub
echo ""
echo "Creating signed binaries..."
echo ""

python3 $LAZARUS_LOC/lz_hub/lz_sign_binary.py $APP_BIN $APP_DIR/build_no $APP_SIGNED_BIN $LAZARUS_LOC/lz_hub/certificates/
if [ $? -ne 0 ] ; then
    echo "Error in script lz_sign_binary.py. Exit.."
	exit
fi

# Flash the signed binaries onto the chip and run the firmware
echo ""
echo "Flashing signed binaries..."
echo ""


if [ $REVISION -eq 1 ]
then
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$APP_SIGNED_BIN" -p LPC55S69 --load-base=0x48000 $BOOTROMSTALL -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$APP_SIGNED_BIN" -p LPC55S69 --load-base=0x48000 --bootromstall 0x50000040 -CoreIndex=0 -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
fi
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Flashing $APP_NAME not successful. Exit.."
    exit
fi

# Restart device
echo ""
echo "Flashing complete: Starting device..."
$MCUX_IDE_BIN/crt_emu_cm_redlink --reset hard -p LPC55S69
# kill all active debug processes
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*

if [ $START_SERVER -eq 1 ] ; then
	python3 $LAZARUS_LOC/lz_hub/lz_hub.py $LAZARUS_LOC/lz_hub/certificates $LAZARUS_LOC/lz_hub/wifi_credentials
fi