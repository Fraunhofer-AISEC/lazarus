#!/usr/bin/env python3

import sys
sys.path.append('protobuf')
import ecdsa
import open_ssl_wrapper as osw
import os
import argparse
import struct
import wifi_credentials
import lz_hub_db
import image_header
from OpenSSL import crypto
from dataclasses import astuple, dataclass
from lz_hub_element_type import ELEMENT_TYPE
from lz_hub_device import get_device


MAGICVAL                            = (0x41495345)
MAX_PUB_ECP_DER_BYTES               = 162
MAX_PUB_ECP_PEM_BYTES               = 279

IMG_HEADER_LEN = 0x800

# Dataclasses for trust anchors and config data (see lz_common.h for c structs)
@dataclass
class LzTrustAnchor:
    magic_trust_anchors: int
    device_id_pub_key_pem: bytearray
    code_auth_pub_key_pem: bytearray
    hub_pub_key_pem: bytearray
    hub_cert_start: int
    hub_cert_size: int
    device_id_cert_start: int
    device_id_cert_size: int
    cursor: int
    cert_bag: bytearray

TRUST_ANCHOR_LENGTH = 4096
TRUST_ANCHOR_FORMAT_WITHOUT_PADDING = f"I{(str(MAX_PUB_ECP_PEM_BYTES) + 's') * 3}HHHHI"
TRUST_ANCHOR_FORMAT = f"{TRUST_ANCHOR_FORMAT_WITHOUT_PADDING}{TRUST_ANCHOR_LENGTH - struct.calcsize(TRUST_ANCHOR_FORMAT_WITHOUT_PADDING)}s"

@dataclass
class LzConfigData:
    img_meta_data: bytearray
    magic_static_symm: int
    static_symm: bytearray
    dev_uuid: bytearray
    magic_nw_data: int
    wifi_ssid: bytearray
    wifi_pwd: bytearray
    wifi_auth_method: bytearray
    server_ip_addr: int
    server_port: int
    padding: bytearray

CONFIG_DATA_LENGTH = 4096
CONFIG_DATA_FORMAT_WITHOUT_PADDING = "64sI32s16sI128s64s32s48sI"
CONFIG_DATA_FORMAT = f"{CONFIG_DATA_FORMAT_WITHOUT_PADDING}{CONFIG_DATA_LENGTH - struct.calcsize(CONFIG_DATA_FORMAT_WITHOUT_PADDING)}s"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("project_path", help="The path where the Lazarus repository is located")
    args = parser.parse_args()
    project_path = args.project_path.rstrip("/")
    print("Specified project path: %s" % os.path.abspath(project_path))
    print("Data provisioning. Loading certs from %s" % project_path)

    # Read hub certificate and private key
    hub_cert = osw.load_cert(project_path + "/lz_hub/certificates/hub_cert.pem")
    if hub_cert is None:
        print("Unable to load all certificates. Exit..")
        return 1
    hub_sk = osw.load_privatekey(project_path + "/lz_hub/certificates/hub_sk.pem")
    if hub_sk is None:
        print("Unable to load all certificates. Exit..")
        return 1

    # Read code signing certificate and private key
    code_auth_cert = osw.load_cert(project_path + "/lz_hub/certificates/code_auth_cert.pem")
    if code_auth_cert is None:
        print("Unable to load all certificates. Exit..")
        return 1
    code_auth_sk = osw.load_privatekey(project_path + "/lz_hub/certificates/code_auth_sk.pem")
    if code_auth_sk is None:
        print("Unable to load all certificates. Exit..")
        return 1

    wifi_params = wifi_credentials.load(project_path + "/lz_hub/wifi_credentials")
    if wifi_params is None:
        return 1

    # Read, provision and flash back the trust anchors
    return issue_device_trust_anchors(project_path, hub_cert, hub_sk, code_auth_cert, code_auth_sk, wifi_params)


def write_single_version_to_db(db, uuid, name, element_type):
    print("Write version of {} to db".format(name))
    payload = get_device(uuid).get_update_file(element_type)
    if payload is None:
        print("failed to get payload of {} for determining the version".format(name))
        return 1

    img_header_bytes = payload[:IMG_HEADER_LEN]
    img_header = image_header.ImageHeader(img_header_bytes)
    version = img_header.version()
    print(f"Version of {name} is: {version}")

    if not lz_hub_db.insert_or_update_version(db, uuid, name, version):
        print("Failed to insert version of {} into database".format(name))
        return 1

    return 0


def write_versions_to_db(db, uuid):
    component_mapping = {
        "app": ELEMENT_TYPE.APP_UPDATE,
        "core": ELEMENT_TYPE.LZ_CORE_UPDATE,
        "udownloader": ELEMENT_TYPE.UD_UPDATE,
        "cpatcher": ELEMENT_TYPE.CP_UPDATE,
    }

    for name, element_type in component_mapping.items():
        if write_single_version_to_db(db, uuid, name, element_type):
            print("Failed to write {} version to database".format(name))
            return 1

    return 0


"""
Reads the trust anchor data structure from flash, provisions the trust anchors and
flashes the data back onto the device including the hub certificate and signed
DeviceID certificate
"""
def issue_device_trust_anchors(project_path, hub_cert, hub_sk, code_auth_cert, code_auth_sk, wifi_params):
    # Load Lazarus Data Store including Trust Anchors from Flash
    print("Reading trust anchors file..")
    try:
        with open(project_path + "/lz_hub/trust_anchors.bin", 'rb') as input_file:
            raw_data = bytearray(input_file.read())
    except Exception as e:
        print("Unable to read trust anchors file: %s. Exit.." % str(e))
        return 1

    print("Unpacking trust anchors structure..")
    try:
        # Lazarus Data Store
        trust_anchor = LzTrustAnchor(*struct.unpack(TRUST_ANCHOR_FORMAT, raw_data[:TRUST_ANCHOR_LENGTH]))
        config_data = LzConfigData(*struct.unpack(CONFIG_DATA_FORMAT, raw_data[TRUST_ANCHOR_LENGTH:]))

    except Exception as e:
        print("Unable to unpack trust anchors from raw-data: %s (length raw_data = %d). Exit.." % (str(e), len(raw_data)))
        return 1

    # ----------------------------------------------------------------
    # ------------ Provision the trust anchors structures ------------
    # ----------------------------------------------------------------

    trust_anchor.code_auth_pub_key_pem = osw.dump_publickey(code_auth_cert.get_pubkey())

    device_id_csr_raw = trust_anchor.cert_bag[trust_anchor.device_id_cert_start:trust_anchor.device_id_cert_start + trust_anchor.device_id_cert_size]
    device_id_csr_string = device_id_csr_raw.decode('utf-8')

    # Read the DeviceID CSR
    device_id_csr = osw.load_csr_from_buffer(device_id_csr_string)
    if device_id_csr is None:
        print("Unable to load DeviceID CSR. Exit..")
        return 1

    print("Successfully loaded CSR")

    # Create a new, hub-signed DeviceID certificate with the extracted public DeviceID key
    device_id_cert_signed = osw.create_cert_from_csr(device_id_csr, hub_sk, hub_cert, True)

    # Convert to raw format to store it in cert bag
    device_id_cert_signed_raw = osw.dump_cert(device_id_cert_signed)
    device_id_cert_size = len(device_id_cert_signed_raw)

    # Create the certificate bag which contains the hub certificate and the DeviceID certificate and
    # fill the corresponding size and start variables
    hub_cert_raw = osw.dump_cert(hub_cert)
    hub_cert_size = len(hub_cert_raw)
    print(f"Signed hub_cert: {device_id_cert_signed_raw}")

    trust_anchor.hub_cert_start = 0
    trust_anchor.hub_cert_size = hub_cert_size
    trust_anchor.device_id_cert_start = hub_cert_size
    trust_anchor.device_id_cert_size = device_id_cert_size
    trust_anchor.cursor = hub_cert_size + device_id_cert_size

    trust_anchor.cert_bag = hub_cert_raw + device_id_cert_signed_raw + bytearray(4096 - (hub_cert_size + device_id_cert_size))

    # Store the hub public key
    trust_anchor.hub_pub_key_pem = osw.dump_publickey(hub_cert.get_pubkey())

    # Set trust anchors magic val: TrusAnchors.info.magic = MAGICVAL to sign that device is now provisioned
    trust_anchor.magic_trust_anchors = MAGICVAL

    # ----------------------------------------------------------------
    # ---------- Provision the network data info structure -----------
    # ----------------------------------------------------------------
    config_data.magic_nw_data = MAGICVAL
    config_data.wifi_auth_method = bytearray(len(config_data.wifi_auth_method))
    config_data.wifi_pwd = bytearray(wifi_params['pwd'], 'utf-8') + bytearray(len(config_data.wifi_pwd) - len(wifi_params['pwd']))
    config_data.wifi_ssid = bytearray(wifi_params['ssid'], 'utf-8') + bytearray(len(config_data.wifi_ssid) - len(wifi_params['ssid']))
    config_data.server_ip_addr = bytearray(wifi_params['ip'], 'utf-8') + bytearray(len(config_data.server_ip_addr) - len(wifi_params['ip']))
    config_data.server_port = wifi_params['port']

    # ----------------------------------------------------------------
    # ------------- Store device in database -------------------------
    # ----------------------------------------------------------------
    db = lz_hub_db.connect()
    if not lz_hub_db.insert_device(db, config_data.dev_uuid, "testdevice", "cortex_m", device_id_cert_signed_raw, config_data.static_symm):
        print("ERROR: Failed to store device in database. Exit..")
        return 1

    print("Write versions of binaries to database..")
    if write_versions_to_db(db, config_data.dev_uuid):
        print("ERROR: Failed to store device version in database. Exit..")
        return 1
    print(lz_hub_db.get_device_versions(db, config_data.dev_uuid))
    lz_hub_db.close(db)


    # Create the trust anchors c structure
    try:
        data_store = struct.pack(TRUST_ANCHOR_FORMAT + CONFIG_DATA_FORMAT, *astuple(trust_anchor), *astuple(config_data))
    except Exception as e:
        print("Unable to pack trust anchors to raw-data: %s. Exit.." % str(e))
        return 1

    # Store the trust anchors
    print("Writing trust anchors to trust_anchors_signed.bin..")
    try:
        with open(project_path + "/lz_hub/trust_anchors_signed.bin", 'wb') as output_file:
            output_file.write(data_store)
    except Exception as e:
        print("Unable to write trust anchors to file: %s. Exit.." % str(e))
        return 1

    print("Completed. Exit..")
    return 0


if __name__ == "__main__":
    ret = main()
    sys.exit(ret)
