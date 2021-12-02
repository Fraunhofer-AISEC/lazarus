#!/bin/bash

# Read optional -c and -e parameter to determine if cleanup should be performed
CLEAN_PROJECTS=0
ERASE_FLASH=0
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

# Clean all projects if command line option -c | --clean was specified
if [ $CLEAN_PROJECTS -eq 1 ] ; then
	cd $SCRIPT_DIR/../lz_dicepp
    make -r -j$CPU_CORES clean
    if [ $? -ne 0 ] ; then
        echo "lz_dicepp clean not successful. Exit.."
        exit
    fi

    cd $SCRIPT_DIR/../lz_core
    make -r -j$CPU_CORES clean
    if [ $? -ne 0 ] ; then
        echo "lz_core clean not successful. Exit.."
        exit
    fi

    cd $SCRIPT_DIR/../lz_cpatcher
    make -r -j$CPU_CORES clean
    if [ $? -ne 0 ] ; then
        echo "lz_cpatcher clean not successful. Exit.."
        exit
    fi

    cd $SCRIPT_DIR/../lz_udownloader
    make -r -j$CPU_CORES clean
    if [ $? -ne 0 ] ; then
        echo "lz_udownloader clean not successful. Exit.."
        exit
    fi

    cd $SCRIPT_DIR/../lz_demo_app
    make -r -j$CPU_CORES clean
    if [ $? -ne 0 ] ; then
        echo "lz_demo_app clean not successful. Exit.."
        exit
    fi

    cd $SCRIPT_DIR
fi

# Build all projects
cd ../lz_dicepp
make -r -j$CPU_CORES all
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "lz_dicepp build not successful. Exit.."
	exit
fi

cd $SCRIPT_DIR/../lz_core
make -r -j$CPU_CORES all
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "lz_core build not successful. Exit.."
	exit
fi

cd $SCRIPT_DIR/../lz_cpatcher
make -r -j$CPU_CORES all
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "lz_cpatcher build not successful. Exit.."
	exit
fi

cd $SCRIPT_DIR/../lz_udownloader
make -r -j$CPU_CORES all
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "re_udownloader build not successful. Exit.."
	exit
fi

cd $SCRIPT_DIR/../lz_demo_app
make -r -j$CPU_CORES all
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "lz_demo_app build not successful. Exit.."
	exit
fi

cd $SCRIPT_DIR

# kill all active debug processes
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*


# Load and sign the generated binaries and store them
cd $SCRIPT_DIR
echo "$(pwd)"
echo ""
echo "Creating signed binaries..."
echo ""
python3 lz_sign_binary.py ../lz_core/build/lz_core.bin ../lz_core/build_no ../lz_core/build/lz_core_signed.bin ./certificates/
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Error in script lz_sign_binary.py. Exit.."
	exit
fi

python3 lz_sign_binary.py ../lz_cpatcher/build/lz_cpatcher.bin ../lz_core/build_no ../lz_cpatcher/build/lz_cpatcher_signed.bin ./certificates/
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Error in script lz_sign_binary.py. Exit.."
	exit
fi

python3 lz_sign_binary.py ../lz_udownloader/build/lz_udownloader.bin ../lz_udownloader/build_no ../lz_udownloader/build/lz_udownloader_signed.bin ./certificates/
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Error in script lz_sign_binary.py. Exit.."
	exit
fi

python3 lz_sign_binary.py ../lz_demo_app/build/lz_demo_app.bin ../lz_demo_app/build_no ../lz_demo_app/build/lz_demo_app_signed.bin ./certificates/
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Error in script lz_sign_binary.py. Exit.."
	exit
fi


# Flash the signed binaries onto the chip and run the firmware
echo ""
echo "Flashing signed binaries..."
echo ""

$MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_core/build/lz_core_signed.bin" -p LPC55S69 --load-base=0x10010000 --flash-driver-reset SYSRESETREQ --bootromstall 0x0  -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Flashing lz_core not successful. Exit.."
    exit
fi

$MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_cpatcher/build/lz_cpatcher_signed.bin" --load-base=0x10028000 -p LPC55S69 --flash-driver-reset SYSRESETREQ --bootromstall 0x0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Flashing lz_cpatcher not successful. Exit.."
    exit
fi

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

$MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_demo_app/build/lz_demo_app_signed.bin" -p LPC55S69 --load-base=0x48000 --flash-driver-reset SYSRESETREQ --bootromstall 0x0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Flashing lz_demo_app not successful. Exit.."
    exit
fi

$MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_dicepp/build/lz_dicepp.bin" -p LPC55S69 --load-base=0x10000000 --flash-driver-reset SYSRESETREQ --bootromstall 0x0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Flashing lz_dicepp not successful. Exit.."
    exit
fi

# If flash was erased, fill the dice++ data store memory area with zeros (otherwise this area is not accessible and dice++ will fail when trying to read from it)
# This must be performed AFTER dicepp was flashed, otherwise it is overwritten by DICEpp
if [ $ERASE_FLASH -eq 1 ] ; then

	echo
	echo "Fill dice++ data store with zeros.."
	echo
	$MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "lz_dicepp_datastore.bin" -p LPC55S69 --load-base=0x1000F800 --flash-driver-reset SYSRESETREQ --bootromstall 0x0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
	EXIT_CODE=$?
	pkill --signal 9 -f .*redlink.*
	pkill --signal 9 -f .*crt_emu_.*
	pkill --signal 9 -f .*arm-none-eabi-gdb.*
	echo
	echo
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "Filling lz_dicepp_datastore not successful. Exit.."
        exit
    fi
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
	python3 lz_hub.py ./certificates ./wifi_credentials
fi
