#!/bin/bash

MCUX_WORKSPACE_LOC_SET=0
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

if [ $REVISION -eq 1 ]
then
    BOOTROMSTALL="--flash-driver-reset SYSRESETREQ --bootromstall 0x0"
else
    BOOTROMSTALL="--bootromstall 0x50000040"
fi

MCUX_FLASH_DIR0=/usr/local/mcuxpressoide/ide/binaries/Flash
MCUX_FLASH_DIR1=$WORKSPACE_LOC/.mcuxpressoide_packages_support/LPC55S69_support/Flash
MCUX_IDE_BIN=/usr/local/mcuxpressoide/ide/binaries
MCUX_TOOL_LOC=/usr/local/mcuxpressoide/ide/tools/bin

# Check if the workspace exists
if [ ! -d "$MCUX_WORKSPACE_LOC" ]; then
  echo "The workspace $MCUX_WORKSPACE_LOC does not exist. Exit"
  exit
fi

# Check if necessary subfolders exist
if [ ! -d "$MCUX_WORKSPACE_LOC/lazarus/lz_hub/certificates" ]; then
  echo "The required subfolder $MCUX_WORKSPACE_LOC/lazarus/lz_hub/certificates does not exist. Exit"
  exit
fi

# Check if wifi_credentials exist
if [ ! -e "$MCUX_WORKSPACE_LOC/lazarus/lz_hub/wifi_credentials" ]; then
  echo "The required file $MCUX_WORKSPACE_LOC/lazarus/lz_hub/wifi_credentials does not exist. See README for information about this file. Exit"
  exit
fi


SCRIPT_DIR=$(pwd)
echo "$SCRIPT_DIR"

# Add tool location to PATH
export PATH=$MCUX_TOOL_LOC:$PATH

# Clean all projects if command line option -c | --clean was specified
if [ $CLEAN_PROJECTS -eq 1 ] ; then
	cd $SCRIPT_DIR/../lz_dicepp
    make -r -j$CPU_CORES clean
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "lz_dicepp clean not successful. Exit.."
        exit
    fi

    cd $SCRIPT_DIR/../lz_core
    make -r -j$CPU_CORES clean
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "lz_core clean not successful. Exit.."
        exit
    fi

    cd $SCRIPT_DIR/../lz_cpatcher
    make -r -j$CPU_CORES clean
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "lz_cpatcher clean not successful. Exit.."
        exit
    fi

    cd $SCRIPT_DIR/../lz_udownloader
    make -r -j$CPU_CORES clean
    if [ $EXIT_CODE -ne 0 ] ; then
        echo "lz_udownloader clean not successful. Exit.."
        exit
    fi

    cd $SCRIPT_DIR/../lz_demo_app
    make -r -j$CPU_CORES clean
    if [ $EXIT_CODE -ne 0 ] ; then
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
    echo "lz_udownloader build not successful. Exit.."
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

# If the flash was erased, the Dice++ Datastore Area must be filled with zeros. This is included in the Lazarus Core Binary because the flashing routine can only flash full sectors
python3 lz_sign_binary.py -c -e ../lz_core/build/lz_core.bin ../lz_core/build_no ../lz_core/build/lz_core_signed.bin ./certificates/

if [ $? -ne 0 ] ; then
    echo "Error in script lz_sign_binary.py. Exit.."
	exit
fi

python3 lz_sign_binary.py ../lz_cpatcher/build/lz_cpatcher.bin ../lz_cpatcher/build_no ../lz_cpatcher/build/lz_cpatcher_signed.bin ./certificates/

if [ $? -ne 0 ] ; then
    echo "Error in script lz_sign_binary.py. Exit.."
	exit
fi

python3 lz_sign_binary.py ../lz_udownloader/build/lz_udownloader.bin ../lz_udownloader/build_no ../lz_udownloader/build/lz_udownloader_signed.bin ./certificates/

if [ $? -ne 0 ] ; then
    echo "Error in script lz_sign_binary.py. Exit.."
	exit
fi

python3 lz_sign_binary.py ../lz_demo_app/build/lz_demo_app.bin ../lz_demo_app/build_no ../lz_demo_app/build/lz_demo_app_signed.bin ./certificates/

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
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 $BOOTROMSTALL -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 --bootromstall 0x50000040 -CoreIndex=0 --flash-driver= -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --PreconnectScript LS_preconnect_LPC55xx.scp --flash-hashing
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
        $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 $BOOTROMSTALL -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
    else
        $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p LPC55S69 --bootromstall 0x50000040 -CoreIndex=0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
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
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_dicepp/build/lz_dicepp.bin" -p LPC55S69 --load-base=0x10000000 $BOOTROMSTALL -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
else
    # In revision 2, lz_core is flashed first
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_core/build/lz_core_signed.bin" -p LPC55S69 --load-base=0x10008000 --bootromstall 0x50000040 -CoreIndex=0  -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
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
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_core/build/lz_core_signed.bin" -p LPC55S69 --load-base=0x10008000 $BOOTROMSTALL  -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_cpatcher/build/lz_cpatcher_signed.bin" --load-base=0x10028000 -p LPC55S69 --bootromstall 0x50000040 -CoreIndex=0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
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
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_cpatcher/build/lz_cpatcher_signed.bin" --load-base=0x10028000 -p LPC55S69 $BOOTROMSTALL -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_udownloader/build/lz_udownloader_signed.bin" -p LPC55S69 --load-base=0x38000 --bootromstall 0x50000040 -CoreIndex=0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
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
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_udownloader/build/lz_udownloader_signed.bin" -p LPC55S69 --load-base=0x38000 $BOOTROMSTALL -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_demo_app/build/lz_demo_app_signed.bin" -p LPC55S69 --load-base=0x48000 --bootromstall 0x50000040 -CoreIndex=0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
fi
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Flashing lz_demo_app/lz_udownloader not successful. Exit.."
    exit
fi

if [ $REVISION -eq 1 ]
then
    # ... than lz_demoapp
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_demo_app/build/lz_demo_app_signed.bin" -p LPC55S69 --load-base=0x48000 $BOOTROMSTALL -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "$MCUX_WORKSPACE_LOC/lazarus/lz_dicepp/build/lz_dicepp.bin" -p LPC55S69 --load-base=0x10000000 --bootromstall 0x50000040 -CoreIndex=0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
fi
EXIT_CODE=$?
pkill --signal 9 -f .*redlink.*
pkill --signal 9 -f .*crt_emu_.*
pkill --signal 9 -f .*arm-none-eabi-gdb.*
echo
echo
if [ $EXIT_CODE -ne 0 ] ; then
    echo "Flashing lz_dicepp/lz_demo_app not successful. Exit.."
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
python3 lz_data_provisioning.py $MCUX_WORKSPACE_LOC/lazarus/
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
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "trust_anchors_signed.bin" -p LPC55S69 --load-base=0x70000 $BOOTROMSTALL -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "trust_anchors_signed.bin" -p LPC55S69 --load-base=0x70000 --bootromstall 0x50000040 -CoreIndex=0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
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
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "staging_area.bin" -p LPC55S69 --load-base=0x72000 $(BOOTROMSTALL) -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1
else
    $MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load "staging_area.bin" -p LPC55S69 --load-base=0x72000 --bootromstall 0x50000040 -CoreIndex=0 -x . --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --flash-hashing --PreconnectScript LS_preconnect_LPC55xx.scp
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
	python3 lz_hub.py ./certificates ./wifi_credentials
fi
