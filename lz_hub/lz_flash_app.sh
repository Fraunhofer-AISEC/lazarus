#!/bin/bash

print () {
    printf "\033[0;32m$1\033[0m\n"
}

print_err () {
    printf "\033[0;31m$1\033[0m\n"
}

kill_debug () {
    # kill all active debug processes
    pkill --signal 9 -f .*redlink.*
    pkill --signal 9 -f .*crt_emu_.*
    pkill --signal 9 -f .*arm-none-eabi-gdb.*
}

CLEAN_PROJECTS=0
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

print "Provisioning Lazarus with non-secure app $APP_NAME (binary: $APP_BIN, location: $APP_DIR).."

# Check if the workspace exists
if [ ! -d "$LAZARUS_LOC" ]; then
  print_err "The workspace $LAZARUS_LOC does not exist. Exit"
  exit
fi

# Check if necessary subfolders exist
if [ ! -d "$LAZARUS_LOC/lz_hub/certificates" ]; then
  print_err "The required subfolder $LAZARUS_LOC/lz_hub/certificates does not exist. Exit"
  exit
fi

# Add tool location to PATH
export PATH=$MCUX_TOOL_LOC:$PATH

# Clean app if command line option -c | --clean was specified
if [ $CLEAN_PROJECTS -eq 1 ] ; then
    cd $APP_DIR
    make -r -j$CPU_CORES clean
    if [ $EXIT_CODE -ne 0 ] ; then
        print_err "$APP_NAME clean not successful. Exit.."
        exit
    fi
fi

# Build app
cd $APP_DIR
make -r -j$CPU_CORES all
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    print_err "$APP_NAME build not successful. Exit.."
	exit
fi

# Flash the signed binaries onto the chip and run the firmware
print "Flashing app.."

$MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$APP_SIGNED_BIN" -p LPC55S69 --load-base=0x00050000 --flash-driver-reset SOFT $BOOTROMSTALL -CoreIndex=0  -x $LAZARUS_LOC/lz_hub/lpc55s69-flash/app --flash-dir $MCUX_FLASH_DIR --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp

EXIT_CODE=$?
kill_debug
if [ $EXIT_CODE -ne 0 ] ; then
    print_err "Flashing not successful. Exit.."
    exit
fi

# Restart device
print "Flashing complete: Starting device.."
$MCUX_IDE_BIN/crt_emu_cm_redlink --reset hard -p LPC55S69
# kill all active debug processes
kill_debug

# Start server if requested
if [ $START_SERVER -eq 1 ] ; then
	python3 $LAZARUS_LOC/lz_hub/lz_hub.py $LAZARUS_LOC/lz_hub/certificates $LAZARUS_LOC/lz_hub/wifi_credentials
fi