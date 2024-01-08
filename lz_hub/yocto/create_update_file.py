from sign_and_verify import sign
from Crypto.Hash import SHA256
from cbor2 import dumps
import sys
from typing import Union

FW_UBOOT: int = 1
FW_LINUX: int = 2
FW_DOWNLOAD: int = 3
FW_IMXBOOT: int = 4

def CreateMetaDataCbor(firmwareImage:bytes, metadata: dict[str, int]) -> bytes:
    update_dict: dict[str, Union[int, str, bytes]] = {
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
        "updateHash": SHA256.new(firmwareImage).digest(),
        "updateFile": firmwareImage,
    }

    update_metadata = dumps(update_dict)
    return update_metadata


def requestUserInput() -> dict[str, int]:
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
    bl_spl_req = int(input("Which early-stage bootloader version is required (Natural Number)?"))
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


def metadataFromParameters() -> tuple[str, dict[str, int]]:
    fw_name = sys.argv[1]
    fw_type = 0

    if(fw_name == "download"):
       fw_type=FW_DOWNLOAD
       out_name="downloader.update"
    elif(fw_name == "production"):
       fw_type=FW_LINUX
       out_name="production.update"
    elif(fw_name == "bootloader_proper"):
       fw_type=FW_UBOOT
       out_name="uboot_proper.update"
    elif(fw_name == "bootloader_early"):
       fw_type=FW_IMXBOOT
       out_name="uboot_spl.update"
    else:
        raise ValueError(f"Unknown firmware name: {fw_name}")

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


def CreateUpdateContainer(update_metadata_cbor: bytes, key:str, filename:str) -> None:
    container=sign(update_metadata_cbor, key)
    f=open(filename,"wb")
    f.write(container)
    f.close()
    print("CBOR saved under "+filename)


def Main() -> None:

    #metadata=requestUserInput()
    outputFilename, metadata=metadataFromParameters()

    filenames: dict[int, str] = dict([(FW_IMXBOOT,"imx-boot"), (FW_LINUX,"productionImage"),(FW_DOWNLOAD, "downloaderImage"), (FW_UBOOT, "u-boot.itb")])

    fwImage = open(filenames[metadata["fwType"]], "rb").read()
    keyname="../certificates/update-linux-sign-private-4096.pem"
    CreateUpdateContainer(CreateMetaDataCbor(fwImage, metadata), keyname, outputFilename)






if __name__ == '__main__':
    Main()
