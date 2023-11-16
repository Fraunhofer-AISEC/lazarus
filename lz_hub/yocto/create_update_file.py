#based on https://www.youtube.com/watch?v=LJTaPaFGmM4
from pickletools import uint8
from sign_and_verify import sign, hash
from cbor2 import dumps
import time
import datetime
import ctypes
import sys

FW_UBOOT: ctypes.c_uint64 = 1
FW_LINUX: ctypes.c_uint64 = 2
FW_DOWNLOAD: ctypes.c_uint64 = 3
FW_IMXBOOT: ctypes.c_uint64 = 4

def CreateMetaDataCbor(firmwareImage, metadata):
    update_dict: dict[ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, str, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, str, bytes, bytes] = {
        "manVer": 1,
        "fwVer": metadata["fwVer"],
        "fwType": metadata["fwType"],
        "devClass": "Apalis iMX8QM",
        "expiry": 0,
        "ubootSplReq": metadata["ubootSplReq"],
        "ubootProperReq": metadata["ubootProperReq"],
        "linuxReq": metadata["linuxReq"],
        "downloadReq": metadata["downloadReq"],
        "updateHashAlgo": "sha256",
        "updateHash": hash(firmwareImage),
        "updateFile": firmwareImage,
    }

    update_metadata = dumps(update_dict)
    return update_metadata


def requestUserInput():
    fw_name = ""
    fw_type = 0
    while (fw_name != "download" and fw_name != "bootloader_proper" and fw_name != "bootloader_early" and fw_name != "production"):
       fw_name = input("Choose the firmware type (download, bootloader_early, bootloader_proper, production): ")
       if(fw_name == "download"):
           fw_type=FW_DOWNLOAD
       if(fw_name == "production"):
           fw_type=FW_LINUX
       if(fw_name == "bootloader_proper"):
           fw_type=FW_UBOOT
       if(fw_name == "bootloader_early"):
           fw_type=FW_IMXBOOT

    
    fw_version = int(input("What is the firmware's version (Natural Number)?"))
    bl_spl_req = int(input("Whhich early-stage bootloader version is required (Natural Number)?"))
    bl_proper_req = int(input("Which bootloader proper version is required (Natural Number)?"))
    prod_req = int(input("Which production image version is required (Natural Number)?"))
    down_req = int(input("Which downloader version is required (Natural Number)?"))

    
    user_input = {
        "fwVer": fw_version,
        "fwType": fw_type,
        "ubootSplReq": bl_spl_req,
        "ubootProperReq": bl_proper_req,
        "linuxReq": prod_req,
        "downloadReq": down_req
    }
    

    return user_input
      

def metadataFromParameters():
    fw_name = sys.argv[1]
    fw_type = 0

    if(fw_name == "download"):
       fw_type=FW_DOWNLOAD
       out_name="downloader.update"
    if(fw_name == "production"):
       fw_type=FW_LINUX
       out_name="production.update"
    if(fw_name == "bootloader_proper"):
       fw_type=FW_UBOOT
       out_name="uboot_proper.update"
    if(fw_name == "bootloader_early"):
       fw_type=FW_IMXBOOT
       out_name="uboot_spl.update"
    
    fw_version = int(sys.argv[2])
    bl_spl_req = int(sys.argv[3])
    bl_proper_req = int(sys.argv[4])
    prod_req = int(sys.argv[5])
    down_req = int(sys.argv[6])

    user_input = {
        "fwVer": fw_version,
        "fwType": fw_type,
        "ubootSplReq": bl_spl_req,
        "ubootProperReq": bl_proper_req,
        "linuxReq": prod_req,
        "downloadReq": down_req
    }
    

    return out_name, user_input


def CreateUpdateContainer(update_metadata, key, filename):
    container_dict: dict[str, bytes, bytes] = {
        "signatureAlgo": "sha256,rsa4096",
        "signature": sign(update_metadata, key),
        "payload": update_metadata
    }

    container=dumps(container_dict)

    f=open(filename,"wb")
    f.write(container)
    f.close()
    print("CBOR saved under "+filename)





def Main():
    
    #metadata=requestUserInput()
    outputFilename, metadata=metadataFromParameters()

    filenames = dict([(FW_IMXBOOT,"imx-boot"), (FW_LINUX,"productionImage"),(FW_DOWNLOAD, "downloaderImage"), (FW_UBOOT, "u-boot.itb")])
    
    message = open(filenames[metadata["fwType"]], "rb").read()
    keyname="../certificates/update-linux-sign-private-4096.pem"
    CreateUpdateContainer(CreateMetaDataCbor(message, metadata), keyname, outputFilename)
    



    

if __name__ == '__main__':
    Main()
