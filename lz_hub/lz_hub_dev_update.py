from lz_hub_element_type import ELEMENT_TYPE
import os

FW_FILE = "../lz_demo_app/build/lz_demo_app_signed.bin"
UD_FILE = "../lz_udownloader/build/lz_udownloader_signed.bin"
LZ_FILE = "../lz_core/build/lz_core_signed.bin"
CP_FILE = "../lz_cpatcher/build/lz_cpatcher_signed.bin"

FW_FILE_UNSIGNED = "../lz_demo_app/build/lz_demo_app.bin"
UD_FILE_UNSIGNED = "../lz_udownloader/build/lz_udownloader.bin"
LZ_FILE_UNSIGNED = "../lz_core/build/lz_core.bin"
CP_FILE_UNSIGNED = "../lz_cpatcher/build/lz_cpatcher.bin"

def get_update_file(element_type):
    fw_file_name = get_fw_file_name(element_type)

    # Read firmware binary
    try:
        with open(fw_file_name, "rb") as fw_file:
            fw = fw_file.read()
    except Exception as e:
        print("ERR: could not read update - %s" %e)
        return None

    return fw


def get_update_file_unsigned(element_type):
    fw_file_name = get_fw_file_name_unsigned(element_type)

    # Read firmware binary
    try:
        with open(fw_file_name, "rb") as fw_file:
            fw = fw_file.read()
    except Exception as e:
        print("ERR: could not read update - %s" %e)
        return None

    return fw


def get_fw_file_name(element_type):

    if element_type == ELEMENT_TYPE.LZ_CORE_UPDATE:
        return LZ_FILE
    elif element_type == ELEMENT_TYPE.UD_UPDATE:
        return UD_FILE
    elif element_type == ELEMENT_TYPE.CP_UPDATE:
        return CP_FILE
    elif element_type == ELEMENT_TYPE.APP_UPDATE:
        return FW_FILE


def get_fw_file_name_unsigned(element_type):

    if element_type == ELEMENT_TYPE.LZ_CORE_UPDATE:
        return LZ_FILE_UNSIGNED
    elif element_type == ELEMENT_TYPE.UD_UPDATE:
        return UD_FILE_UNSIGNED
    elif element_type == ELEMENT_TYPE.CP_UPDATE:
        return CP_FILE_UNSIGNED
    elif element_type == ELEMENT_TYPE.APP_UPDATE:
        return FW_FILE_UNSIGNED