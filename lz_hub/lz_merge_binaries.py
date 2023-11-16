import sys
import ecdsa
import hashlib
import os
import argparse
import struct
import time

HEADER_SIZE         = 0x800

def main():
    print("Creating merged binary..")

     # Parse the mandatory arguments of the script
    args = parse_arguments()

    try:
        lz_dicepp = open(args.lz_dicepp, "rb").read()
    except Exception as e:
        print("Error: failed to open file %s: %s" %(os.path.abspath(args.lz_dicepp), str(e)))
        return 1

    try:
        lz_core = open(args.lz_core, "rb").read()
    except Exception as e:
        print("Error: failed to open file %s: %s" %(os.path.abspath(args.lz_core), str(e)))
        return 1

    try:
        lz_cpatcher = open(args.lz_cpatcher, "rb").read()
    except Exception as e:
        print("Error: failed to open file %s: %s" %(os.path.abspath(args.lz_cpatcher), str(e)))
        return 1

    try:
        lz_udownloader = open(args.lz_udownloader, "rb").read()
    except Exception as e:
        print("Error: failed to open file %s: %s" %(os.path.abspath(args.lz_udownloader), str(e)))
        return 1

    try:
        lz_app = open(args.lz_app, "rb").read()
    except Exception as e:
        print("Error: failed to open file %s: %s" %(os.path.abspath(args.lz_app), str(e)))
        return 1

    lz_dicepp_fill = bytearray(0x8000 - len(lz_dicepp))
    lz_dice_data_store = bytearray(0x800)
    lz_dice_data_store_fill = bytearray(0x8000 - len(lz_dice_data_store))
    lz_core_fill = bytearray((0x1B400 + 0x800 + 0x400) - len(lz_core))
    lz_cpatcher_fill = bytearray((0xF800 + 0x800) - len(lz_cpatcher))
    lz_udownloader_fill = bytearray((0x13800 + 0x800) - len(lz_udownloader))
    lz_app_fill = bytearray((0x1F800 + 0x800) - len(lz_app))
    lz_data_storage = bytearray(0x2000)
    lz_staging_area = bytearray(0x28000)

    print("lz_dicepp size: %x" %(len(lz_dicepp)))
    print("lz_core size: %x" %(len(lz_core)))
    print("lz_cpatcher size: %x" %(len(lz_cpatcher)))
    print("lz_udownloader size: %x" %(len(lz_udownloader)))
    print("lz_app size: %x" %(len(lz_app)))
    print("")

    lz_merged = bytearray(lz_dicepp + lz_dicepp_fill)
    print("lz_data_store at %x" %len(lz_merged))
    lz_merged = bytearray(lz_merged + lz_dice_data_store + lz_dice_data_store_fill)
    print("lz_core at %x" %len(lz_merged))
    lz_merged = bytearray(lz_merged + lz_core + lz_core_fill)
    print("lz_cpatcher at %x" %len(lz_merged))
    lz_merged = bytearray(lz_merged + lz_cpatcher + lz_cpatcher_fill)
    print("lz_udownloader at %x" %len(lz_merged))
    lz_merged = bytearray(lz_merged + lz_udownloader + lz_udownloader_fill)
    print("lz_app at %x" %len(lz_merged))
    lz_merged = bytearray(lz_merged + lz_app + lz_app_fill)
    print("lz_data_storage at %x" %len(lz_merged))
    lz_merged = bytearray(lz_merged + lz_data_storage)
    print("lz_staging_area at %x" %len(lz_merged))
    lz_merged = bytearray(lz_merged + lz_staging_area)

    try:
        with open(args.out_file, "wb") as out_file:
            out_file.write(lz_merged)
    except Exception as e:
        print("Failed to write signed binary to file: %s" %str(e))
        return 1

    print("Successfully created merged binary %s" %os.path.basename(args.out_file))

    return 0


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("lz_dicepp", help="The lz_dicepp signed binary path")
    parser.add_argument("lz_core", help="The lz_core signed binary path")
    parser.add_argument("lz_cpatcher", help="The lz_cpatcher signed binary path")
    parser.add_argument("lz_udownloader", help="The lz_udownloader signed binary path")
    parser.add_argument("lz_app", help="The app signed binary path")
    parser.add_argument("out_file", help="Name of the merged binary")

    args = parser.parse_args()
    args.lz_dicepp = args.lz_dicepp.rstrip("/")
    args.lz_core = args.lz_core.rstrip("/")
    args.lz_cpatcher = args.lz_cpatcher.rstrip("/")
    args.lz_udownloader = args.lz_udownloader.rstrip("/")
    args.lz_app = args.lz_app.rstrip("/")
    args.out_file = args.out_file.rstrip("/")

    print("Specified lz_dicepp file: %s" %os.path.abspath(args.lz_dicepp))
    print("Specified lz_core file: %s" %os.path.abspath(args.lz_core))
    print("Specified lz_cpatcher path: %s" %os.path.abspath(args.lz_cpatcher))
    print("Specified lz_udownloader path: %s" %os.path.abspath(args.lz_udownloader))
    print("Specified lz_app file: %s" %os.path.abspath(args.lz_app))
    print("Specified out_file path: %s" %os.path.abspath(args.out_file))

    return args


if __name__ == "__main__":
    ret = main()
    sys.exit(ret)
