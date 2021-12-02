#!/bin/bash

# Read optional -c and -e parameter to determine if cleanup should be performed
CLEAN_PROJECTS=0
START_SERVER=0
MCUX_WORKSPACE_LOC_SET=0
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
	-p=*|--path=*)
        MCUX_WORKSPACE_LOC="${arg#*=}"
        shift # Remove --cache= from processing
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

# Check if workspace directory is set
if [ $MCUX_WORKSPACE_LOC_SET -eq 0 ]; then
    echo "Usage: $0 [OPTIONS] <mcuxpresso-workspace-path>"
  exit
fi

# Check if workspace directory exists
if [ ! -d "$MCUX_WORKSPACE_LOC" ]; then
  echo "The workspace $MCUX_WORKSPACE_LOC does not exist. Exit"
  exit
fi

# Check if necessary subfolders exist
if [ ! -d "$MCUX_WORKSPACE_LOC/lazarus/lz_hub/certificates" ]; then
  echo "The required subfolder $MCUX_WORKSPACE_LOC/lazarus/lz_hub/certificates does not exist. Exit"
  exit
fi

MCUX_FLASH_DIR1=$MCUX_WORKSPACE_LOC/.mcuxpressoide_packages_support/LPC55S69_support/Flash
MCUX_TOOL_LOC=/usr/local/mcuxpressoide/ide/tools/bin
MCUX_IDE_BIN=/usr/local/mcuxpressoide/ide/binaries
MCUX_FLASH_DIR0=$MCUX_IDE_BIN/Flash
SCRIPT_DIR=$(pwd)
echo "$SCRIPT_DIR"

# Add tool location to PATH
export PATH=$MCUX_TOOL_LOC:$PATH

# Clean project if command line option -c | --clean was specified
if [ $CLEAN_PROJECTS -eq 1 ] ; then
    cd $SCRIPT_DIR/../lz_udownloader
    make -r -j$CPU_CORES clean
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "lz_udownloader clean not successful. Exit.."
        exit
    fi

    cd $SCRIPT_DIR
fi

# Build project
cd $SCRIPT_DIR/../lz_udownloader
make -r -j$CPU_CORES all
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "lz_udownloader build not successful. Exit.."
	exit
fi

cd $SCRIPT_DIR

# kill all active debug processes
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*


# Flash the signed binaries onto the chip and run the firmware
echo ""
echo "Flashing signed binary..."
echo ""

$MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_udownloader/build/lz_udownloader_signed.bin" -p LPC55S69 --load-base=0x38000 --flash-driver-reset SYSRESETREQ --bootromstall 0x0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Flashing lz_udownloader not successful. Exit.."
    exit
fi

# Restart device
echo ""
echo "Provisioning complete: Restarting device..."
$MCUX_IDE_BIN/crt_emu_cm_redlink --reset hard -p LPC55S69

# kill all active debug processes
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*

if [ $START_SERVER -eq 1 ] ; then
	python3 lz_hub.py ./certificates ./wifi_credentials
fi
