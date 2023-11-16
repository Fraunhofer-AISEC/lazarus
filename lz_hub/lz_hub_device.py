#!/usr/bin/env python3

import sys
sys.path.append('protobuf')
import hashlib
import lz_hub_db
import image_header
from lz_hub_element_type import ELEMENT_TYPE
from lz_fitimage import get_config_hash_file_name
from ecdsa.util import sigencode_der
from datetime import datetime
import cbor2
import hubrequest_pb2
import hubresponse_pb2
import bootticket_request_pb2
import bootticket_response_pb2
from abc import ABC, abstractmethod

class HubException(Exception):
    pass

IMG_HEADER_LEN          = 0x800

class Device(ABC):
    def __init__(self, uuid):
        self.uuid = uuid

        db = lz_hub_db.connect()
        _name, _class, _awdt_period_s, _status, _index, _temperature, _humidity = lz_hub_db.get_device_info(db, self.uuid)
        lz_hub_db.close(db)

        self.name = _name
        self.cls = _class

    @abstractmethod
    def get_boot_ticket_response(self, nonce, hub_cb):
        pass

    @abstractmethod
    def core_digest(self):
        pass

    @abstractmethod
    def get_update_payload(self, update_type):
        pass

    @abstractmethod
    def get_update_version(self, component):
        pass


class CortexMDevice(Device):
    def __init__(self, uuid):
        super().__init__(uuid)

        self.files = {
            "FW_FILE": "../lz_demo_app/build/lz_demo_app_signed.bin",
            "UD_FILE": "../lz_udownloader/build/lz_udownloader_signed.bin",
            "LZ_FILE": "../lz_core/build/lz_core_signed.bin",
            "CP_FILE": "../lz_cpatcher/build/lz_cpatcher_signed.bin",
            "FW_FILE_UNSIGNED": "../lz_demo_app/build/lz_demo_app.bin",
            "UD_FILE_UNSIGNED": "../lz_udownloader/build/lz_udownloader.bin",
            "LZ_FILE_UNSIGNED": "../lz_core/build/lz_core.bin",
            "CP_FILE_UNSIGNED": "../lz_cpatcher/build/lz_cpatcher.bin",
        }


    def get_boot_ticket_response(self, nonce, hub_cb):
        dicepp_info = bootticket_response_pb2.FirmwareInfoDicepp()
        response = bootticket_response_pb2.HubResponseRefreshBootTicket()
        response.nonce = nonce
        response.dicepp.CopyFrom(dicepp_info)

        return response

    def sha256(self, message):
        return hashlib.sha256(message).digest()

    def core_digest(self):
        # Read lz_core binary
        lz_core = self.get_update_file_unsigned(ELEMENT_TYPE.LZ_CORE_UPDATE)
        if lz_core is None:
            print("ERROR: Could not read lazarus core binary for dev_auth calculation")
            return None

        # Paper: Software Version M_x. This is the hashed current lz_core binary
        lz_core_digest = self.sha256(lz_core)

        return lz_core_digest

    def get_update_payload(self, update_type):
        if update_type == "core":
            element_type = ELEMENT_TYPE.LZ_CORE_UPDATE
        elif update_type == "app":
            element_type = ELEMENT_TYPE.APP_UPDATE
        elif update_type == "udownloader":
            element_type = ELEMENT_TYPE.UD_UPDATE
        elif update_type == "cpatcher":
            element_type = ELEMENT_TYPE.CP_UPDATE
        else:
            raise HubException("Invalid update type \"{}\"".format(update_type))

        return self.get_update_file(element_type)

    def get_update_version(self, component):
        payload = self.get_update_payload(component)
        img_header_bytes = payload[:IMG_HEADER_LEN]

        try:
            img_hdr = image_header.ImageHeader(img_header_bytes)
            print(f"CortexMDevice: Newest version for {component} is {img_hdr.version()}.")
            return img_hdr.name(), img_hdr.version(), img_hdr.issue_time()
        except image_header.ImageHeaderException as e:
            raise HubException("Failed to parse image header: {}".format(e))


    def get_update_file(self, element_type):
        fw_file_name = self.get_fw_file_name(element_type)

        # Read firmware binary
        try:
            with open(fw_file_name, "rb") as fw_file:
                fw = fw_file.read()
                print("update len: {}".format(len(fw)))
        except Exception as e:
            print("ERR: could not read update - %s" %e)
            return None

        return fw


    def get_update_file_unsigned(self, element_type):
        fw_file_name = self.get_fw_file_name_unsigned(element_type)

        # Read firmware binary
        try:
            with open(fw_file_name, "rb") as fw_file:
                fw = fw_file.read()
        except Exception as e:
            print("ERR: could not read update - %s" %e)
            return None

        return fw


    def get_fw_file_name(self, element_type):
        if element_type == ELEMENT_TYPE.LZ_CORE_UPDATE:
            return self.files["LZ_FILE"]
        elif element_type == ELEMENT_TYPE.UD_UPDATE:
            return self.files["UD_FILE"]
        elif element_type == ELEMENT_TYPE.CP_UPDATE:
            return self.files["CP_FILE"]
        elif element_type == ELEMENT_TYPE.APP_UPDATE:
            return self.files["FW_FILE"]


    def get_fw_file_name_unsigned(self, element_type):
        if element_type == ELEMENT_TYPE.LZ_CORE_UPDATE:
            return self.files["LZ_FILE_UNSIGNED"]
        elif element_type == ELEMENT_TYPE.UD_UPDATE:
            return self.files["UD_FILE_UNSIGNED"]
        elif element_type == ELEMENT_TYPE.CP_UPDATE:
            return self.files["CP_FILE_UNSIGNED"]
        elif element_type == ELEMENT_TYPE.APP_UPDATE:
            return self.files["FW_FILE_UNSIGNED"]


class CortexADevice(Device):
    def __init__(self, uuid):
        super().__init__(uuid)

        self.files = {
            "uboot_spl":  "./updates/uboot_spl.update",
            "uboot_proper":  "./updates/uboot_proper.update",
            "downloader":  "./updates/downloader.update",
            "production":  "./updates/production.update",
            "uboot_spl_unsigned":  "./updates/imx-boot",
            "u_boot_proper_unsigned": "./updates/u-boot.itb",
            "downloader_unsigned": "./updates/downloadImage",
            "production_unsigned": "./updates/productionImage",
        }

    def get_boot_ticket_response(self, nonce, hub_cb):
        tpm_info = bootticket_response_pb2.FirmwareInfoTpm()
        response = bootticket_response_pb2.HubResponseRefreshBootTicket()
        response.nonce = nonce
        response.tpm.CopyFrom(tpm_info)

        boot_nonce = int.from_bytes(nonce, 'little')
        config_hash = get_config_hash_file_name(self.files['production_unsigned'])

        inner_ticket = int.to_bytes(boot_nonce, 8, 'big') + config_hash
        signature = hub_cb.hub_sk_ecdsa.sign(
            inner_ticket,
            hashfunc=hashlib.sha256,
            sigencode=sigencode_der)
        sig_len = int.to_bytes(len(signature), 1, 'little')
        pad = b'\x00'*(72-len(signature))
        signed_ticket = inner_ticket + sig_len + signature + pad
        response.tpm.ticket = signed_ticket

        return response

    def core_digest(self):
        file_name = self.files['u_boot_proper_unsigned']
        return get_config_hash_file_name(file_name)

    def get_update_payload(self, name):
        try:
            fw_file_name = self.files[name]
        except KeyError as e:
            print("ERR: could not get update file name - %s" %e)
            return None

        # Read firmware binary
        try:
            with open(fw_file_name, "rb") as fw_file:
                fw = fw_file.read()
                print("update len: {}".format(len(fw)))
        except Exception as e:
            print("ERR: could not read update - %s" %e)
            return None

        return fw

    def get_update_version(self, component):
        payload = self.get_update_payload(component)

        outer_cbor = cbor2.loads(payload)
        inner_cbor = cbor2.loads(outer_cbor['payload'])
        issue_time = int(inner_cbor['fwVer'])
        version = datetime.fromtimestamp(issue_time).strftime("%Y-%m-%d %H:%M:%S")
        print(f"CortexADevice: Newest version for {component} is {version}.")

        return component, version, issue_time


def get_device(uuid):
    db = lz_hub_db.connect()
    _name, _class, _awdt_period_s, _status, _index, _temperature, _humidity = lz_hub_db.get_device_info(db, uuid)
    lz_hub_db.close(db)

    if _class == "cortex_m":
        return CortexMDevice(uuid)
    elif _class == "cortex_a":
        return CortexADevice(uuid)
    else:
        raise Exception(f"Unsupported device class {_class}")
