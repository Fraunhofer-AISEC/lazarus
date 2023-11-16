#!/bin/bash

set -e

print () {
    printf "\033[0;32m$1\033[0m\n"
    return 0
}

print_err () {
    printf "\033[0;31m$1\033[0m\n"
    return 0
}

kill_debug () {
    # kill all active debug processes
    set +e
    pkill --signal 9 -f .*redlink.*
    pkill --signal 9 -f .*crt_emu_.*
    pkill --signal 9 -f .*arm-none-eabi-gdb.*
    set -e
    return 0
}

CLEAN_PROJECTS=0
REVISION=2
CPU_CORES=$(nproc)

for arg in "$@"
do
    case $arg in
    -c|--clean)
        CLEAN_PROJECTS=1
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

# Check if wifi_credentials exist
if [ ! -e "$LAZARUS_LOC/lz_hub/wifi_credentials" ]; then
  print_err "The required file $LAZARUS_LOC/lz_hub/wifi_credentials does not exist. See README for information about this file. Exit"
  exit
fi

# Add tool location to PATH
export PATH=$MCUX_TOOL_LOC:$PATH

print "Cleaning all project.."

# Clean all projects if command line option -c | --clean was specified
if [ $CLEAN_PROJECTS -eq 1 ] ; then
	cd $LAZARUS_LOC/lz_dicepp
    make -r -j$CPU_CORES clean

    cd $LAZARUS_LOC/lz_core
    make -r -j$CPU_CORES clean

    cd $LAZARUS_LOC/lz_cpatcher
    make -r -j$CPU_CORES clean

    cd $LAZARUS_LOC/lz_udownloader
    make -r -j$CPU_CORES clean

    cd $APP_DIR
    make -r -j$CPU_CORES clean
fi

print "Building all projects"

# Build all projects
cd $LAZARUS_LOC/lz_dicepp
make -r -j$CPU_CORES all

cd $LAZARUS_LOC/lz_core
make -r -j$CPU_CORES all

cd $LAZARUS_LOC/lz_cpatcher
make -r -j$CPU_CORES all

cd $LAZARUS_LOC/lz_udownloader
make -r -j$CPU_CORES all

cd $APP_DIR
make -r -j$CPU_CORES all


# Load and sign the generated binaries and store them
cd $LAZARUS_LOC/lz_hub
print "Creating merged binary.."
python3 lz_merge_binaries.py $LAZARUS_LOC/lz_dicepp/build/lz_dicepp.bin $LAZARUS_LOC/lz_core/build/lz_core_signed.bin $LAZARUS_LOC/lz_cpatcher/build/lz_cpatcher_signed.bin $LAZARUS_LOC/lz_udownloader/build/lz_udownloader_signed.bin $LAZARUS_LOC/lz_demo_app/build/lz_demo_app_signed.bin lz_merged.bin

# Mass erase the flash before flashing the projects
# NOTE: Sometimes this does not work, then Jumper J10 has to be set and Reset and then ISP buttons have to be pressed
print "Erasing the flash.."
# kill all active debug processes
kill_debug

if [ $REVISION -eq 1 ]
then
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 --flash-driver-reset SOFT $BOOTROMSTALL -x $LAZARUS_LOC/lz_hub/lpc55s69-flash/binaries --flash-dir $MCUX_FLASH_DIR
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 --flash-driver-reset SOFT --bootromstall 0x50000040 -CoreIndex=0 --flash-driver= -x $LAZARUS_LOC/lz_hub/lpc55s69-flash/binaries --flash-dir $MCUX_FLASH_DIR --PreconnectScript LS_preconnect_LPC55xx.scp --flash-hashing
fi
kill_debug
sleep 1s

# Flash the signed binaries onto the chip and run the firmware
print "Flashing merged binary.."

$MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$LAZARUS_LOC/lz_hub/lz_merged.bin" -p LPC55S69 --load-base=0x10000000 --flash-driver-reset SOFT --bootromstall 0x50000040 -CoreIndex=0  -x $LAZARUS_LOC/lz_hub/lpc55s69-flash/binaries --flash-dir $MCUX_FLASH_DIR --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
kill_debug

# Restart device
print "Flashing complete: Starting device.."
$MCUX_IDE_BIN/crt_emu_cm_redlink --reset hard -p LPC55S69
# kill all active debug processes
kill_debug

# Wait until the firmware has completed
print "Waiting for 5s until the firmware has completed.."
sleep 5s
print "Continuing.."

# Read the Trust Anchors from the flash and store them into a file
print "Reading Trust Anchors from Flash.."
if [ $REVISION -eq 1 ]; then
    $MCUX_TOOL_LOC/arm-none-eabi-gdb -x link2_gdb_read_flash_gdb_commands
else
    $MCUX_TOOL_LOC/arm-none-eabi-gdb -x link2_gdb_read_flash_gdb_commands_rev_2
fi
kill_debug

# Perform provisioning part 2: Create trust anchors and sign device certificate
print "Creating trust anchors and signing device cert.."
python3 $LAZARUS_LOC/lz_hub/lz_data_provisioning.py $LAZARUS_LOC/

# Flash the trust anchors onto the device

print "Flashing trust anchors onto device.."
if [ $REVISION -eq 1 ]
then
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "trust_anchors_signed.bin" -p LPC55S69 --load-base=0x70000 --flash-driver-reset SOFT $BOOTROMSTALL -x $LAZARUS_LOC/lz_hub/lpc55s69-flash/data --flash-dir $MCUX_FLASH_DIR
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "trust_anchors_signed.bin" -p LPC55S69 --load-base=0x70000 --flash-driver-reset SOFT --bootromstall 0x50000040 -CoreIndex=0 -x $LAZARUS_LOC/lz_hub/lpc55s69-flash/data --flash-dir $MCUX_FLASH_DIR --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
fi
kill_debug

# Restart device
print "Provisioning complete: Restarting device.."
$MCUX_IDE_BIN/crt_emu_cm_redlink --reset hard -p LPC55S69
