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

# Check if necessary subfolders exist
if [ ! -d "$LAZARUS_LOC/lz_hub/certificates" ]; then
  echo "The required subfolder $LAZARUS_LOC/lz_hub/certificates does not exist. Exit"
  exit
fi

# Check if wifi_credentials exist
if [ ! -e "$LAZARUS_LOC/lz_hub/wifi_credentials" ]; then
  echo "The required file $LAZARUS_LOC/lz_hub/wifi_credentials does not exist. See README for information about this file. Exit"
  exit
fi

# Add tool location to PATH
export PATH=$MCUX_TOOL_LOC:$PATH

# Clean all projects if command line option -c | --clean was specified
if [ $CLEAN_PROJECTS -eq 1 ] ; then
	cd $LAZARUS_LOC/lz_dicepp
    make -r -j$CPU_CORES clean
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "lz_dicepp clean not successful. Exit.."
        exit
    fi

    cd $LAZARUS_LOC/lz_core
    make -r -j$CPU_CORES clean
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "lz_core clean not successful. Exit.."
        exit
    fi

    cd $LAZARUS_LOC/lz_cpatcher
    make -r -j$CPU_CORES clean
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "lz_cpatcher clean not successful. Exit.."
        exit
    fi

    cd $LAZARUS_LOC/lz_udownloader
    make -r -j$CPU_CORES clean
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "lz_udownloader clean not successful. Exit.."
        exit
    fi

    cd $APP_DIR
    make -r -j$CPU_CORES clean
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "$APP_NAME clean not successful. Exit.."
        exit
    fi
fi

# Build all projects
cd $LAZARUS_LOC/lz_dicepp
make -r -j$CPU_CORES all
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "lz_dicepp build not successful. Exit.."
	exit
fi

cd $LAZARUS_LOC/lz_core
make -r -j$CPU_CORES all
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "lz_core build not successful. Exit.."
	exit
fi

cd $LAZARUS_LOC/lz_cpatcher
make -r -j$CPU_CORES all
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "lz_cpatcher build not successful. Exit.."
	exit
fi

cd $LAZARUS_LOC/lz_udownloader
make -r -j$CPU_CORES all
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "lz_udownloader build not successful. Exit.."
	exit
fi

cd $APP_DIR
make -r -j$CPU_CORES all
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
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

# If the flash was erased, the Dice++ Datastore Area must be filled with zeros. This is included in the Lazarus Core Binary because the flashing routine can only flash full sectors
python3 $LAZARUS_LOC/lz_hub/lz_sign_binary.py -c -e $LAZARUS_LOC/lz_core/build/lz_core.bin $LAZARUS_LOC/lz_core/build_no $LAZARUS_LOC/lz_core/build/lz_core_signed.bin $LAZARUS_LOC/lz_hub/certificates/

if [ $? -ne 0 ] ; then
    echo "Error in script lz_sign_binary.py. Exit.."
	exit
fi

python3 $LAZARUS_LOC/lz_hub/lz_sign_binary.py $LAZARUS_LOC/lz_cpatcher/build/lz_cpatcher.bin $LAZARUS_LOC/lz_cpatcher/build_no $LAZARUS_LOC/lz_cpatcher/build/lz_cpatcher_signed.bin $LAZARUS_LOC/lz_hub/certificates/

if [ $? -ne 0 ] ; then
    echo "Error in script lz_sign_binary.py. Exit.."
	exit
fi

python3 $LAZARUS_LOC/lz_hub/lz_sign_binary.py $LAZARUS_LOC/lz_udownloader/build/lz_udownloader.bin $LAZARUS_LOC/lz_udownloader/build_no $LAZARUS_LOC/lz_udownloader/build/lz_udownloader_signed.bin $LAZARUS_LOC/lz_hub/certificates/

if [ $? -ne 0 ] ; then
    echo "Error in script lz_sign_binary.py. Exit.."
	exit
fi

python3 $LAZARUS_LOC/lz_hub/lz_sign_binary.py $APP_BIN $APP_DIR/build_no $APP_SIGNED_BIN $LAZARUS_LOC/lz_hub/certificates/

if [ $? -ne 0 ] ; then
    echo "Error in script lz_sign_binary.py. Exit.."
	exit
fi

# Mss erase the flash before flashing the projects
# NOTE: Sometimes this does not work, then Jumper J10 has to be set and Reset and then ISP buttons have to be pressed
# if this is the case, dont use the -e|--erase option but perform the cleaning with the link2_erase_flash.sh script
echo ""
echo "Erasing the flash"
echo ""
if [ $REVISION -eq 1 ]
then
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 $BOOTROMSTALL -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 --bootromstall 0x50000040 -CoreIndex=0 --flash-driver= -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR --PreconnectScript LS_preconnect_LPC55xx.scp --flash-hashing
fi

EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Erasing flash failed. Trying again.."
    if [ $REVISION -eq 1 ]
    then
        $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 $BOOTROMSTALL -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR
    else
        $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 --bootromstall 0x50000040 -CoreIndex=0 -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
    fi
    EXIT_CODE=$?
    pkill --signal 9 -f .*redlink.*
    pkill --signal 9 -f .*crt_emu_.*
    pkill --signal 9 -f .*arm-none-eabi-gdb.*
    echo
    echo
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "Erasing flash not successful. Check target connection. It might also be necessary to erase it manually with jumper J10 set and then execute the script again without the -e option. Exit.."
    exit
    fi
fi
sleep 1s


# Flash the signed binaries onto the chip and run the firmware
echo ""
echo "Flashing signed binaries..."
echo ""

if [ $REVISION -eq 1 ]
then
    # In revision 1, lz_dicepp is flashed first
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$LAZARUS_LOC/lz_dicepp/build/lz_dicepp.bin" -p LPC55S69 --load-base=0x10000000 $BOOTROMSTALL -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR
else
    # In revision 2, lz_core is flashed first
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$LAZARUS_LOC/lz_core/build/lz_core_signed.bin" -p LPC55S69 --load-base=0x10008000 --bootromstall 0x50000040 -CoreIndex=0  -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
fi
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    # TODO: Error message according to revision
    echo "Flashing lz_core/lz_dicepp not successful. Exit.."
    exit
fi

if [ $REVISION -eq 1 ]
then
    # ... than lz_core
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$LAZARUS_LOC/lz_core/build/lz_core_signed.bin" -p LPC55S69 --load-base=0x10008000 $BOOTROMSTALL  -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$LAZARUS_LOC/lz_cpatcher/build/lz_cpatcher_signed.bin" --load-base=0x10028000 -p LPC55S69 --bootromstall 0x50000040 -CoreIndex=0 -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
fi
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Flashing lz_cpatcher/lz_core not successful. Exit.."
    exit
fi

if [ $REVISION -eq 1 ]
then
    # ... than lz_cpatcher
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$LAZARUS_LOC/lz_cpatcher/build/lz_cpatcher_signed.bin" --load-base=0x10028000 -p LPC55S69 $BOOTROMSTALL -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$LAZARUS_LOC/lz_udownloader/build/lz_udownloader_signed.bin" -p LPC55S69 --load-base=0x38000 --bootromstall 0x50000040 -CoreIndex=0 -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
fi
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Flashing lz_udownloader/lz_cpatcher not successful. Exit.."
    exit
fi

if [ $REVISION -eq 1 ]
then
    # ... than lz_udownloader
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$LAZARUS_LOC/lz_udownloader/build/lz_udownloader_signed.bin" -p LPC55S69 --load-base=0x38000 $BOOTROMSTALL -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR
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
    echo "Flashing $APP_NAME/lz_udownloader not successful. Exit.."
    exit
fi

if [ $REVISION -eq 1 ]
then
    # ... than lz_demoapp
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$APP_SIGNED_BIN" -p LPC55S69 --load-base=0x48000 $BOOTROMSTALL -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$LAZARUS_LOC/lz_dicepp/build/lz_dicepp.bin" -p LPC55S69 --load-base=0x10000000 --bootromstall 0x50000040 -CoreIndex=0 -x $LAZARUS_LOC/lz_hub --flash-dir $MCUX_FLASH_DIR --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
fi
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Flashing lz_dicepp/$APP_NAME not successful. Exit.."
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

# Wait until the firmware has completed
echo
echo "Waiting for 10s until the firmware has completed..."
sleep 10s
echo "Continuing..."

# Read the Trust Anchors from the flash and store them into a file
echo
echo "Reading trust anchors from flash..."
echo
if [ $REVISION -eq 1 ]
then
    $MCUX_TOOL_LOC/arm-none-eabi-gdb -x link2_gdb_read_flash_gdb_commands
else
    $MCUX_TOOL_LOC/arm-none-eabi-gdb -x link2_gdb_read_flash_gdb_commands_rev_2
fi
EXIT_CODE=$?

pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo

if [ $EXIT_CODE -ne 0 ] ; then
    echo "Reading trust anchors from flash not successful. Exit.."
    exit
fi

# Perform provisioning part 2: Create trust anchors and sign device certificate
echo ""
echo "Creating trust anchors and signing device certificate..."
echo
python3 $LAZARUS_LOC/lz_hub/lz_data_provisioning.py $LAZARUS_LOC/
EXIT_CODE=$?

if [ $EXIT_CODE -ne 2 ] ; then
    echo "Error in script lz_data_provisioning. Exit.."
	exit
fi

# Flash the trust anchors onto the device
echo
echo "Flashing trust anchors onto device..."
echo

if [ $REVISION -eq 1 ]
then
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "trust_anchors_signed.bin" -p LPC55S69 --load-base=0x70000 $BOOTROMSTALL -x $LAZARUS_LOC/lz_hub/ --flash-dir $MCUX_FLASH_DIR
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "trust_anchors_signed.bin" -p LPC55S69 --load-base=0x70000 --bootromstall 0x50000040 -CoreIndex=0 -x $LAZARUS_LOC/lz_hub/ --flash-dir $MCUX_FLASH_DIR --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
fi
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Flashing trust anchors not successful. Exit.."
    exit
fi

# Flashing clean staging area onto device
echo
echo "Flashing clean staging area onto device..."
echo

if [ $REVISION -eq 1 ]
then
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "staging_area.bin" -p LPC55S69 --load-base=0x72000 $(BOOTROMSTALL) -x $LAZARUS_LOC/lz_hub/ --flash-dir $MCUX_FLASH_DIR
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "staging_area.bin" -p LPC55S69 --load-base=0x72000 --bootromstall 0x50000040 -CoreIndex=0 -x $LAZARUS_LOC/lz_hub/ --flash-dir $MCUX_FLASH_DIR --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
fi

pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo

# Restart device
echo ""
echo "Provisioning complete: Restarting device..."
$MCUX_IDE_BIN/crt_emu_cm_redlink --reset hard -p LPC55S69

# kill all active debug processes
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*

if [ $START_SERVER -eq 1 ] ; then
	python3 $LAZARUS_LOC/lz_hub/lz_hub.py $LAZARUS_LOC/lz_hub/certificates $LAZARUS_LOC/lz_hub/wifi_credentials
fi
