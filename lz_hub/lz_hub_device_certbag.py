#!/usr/bin/env python3

import socket
import ecdsa
import struct
from enum import IntEnum
import hashlib
import hmac
import binascii
import OpenSSL
from OpenSSL import crypto
import open_ssl_wrapper as osw
import argparse
import os
import base64
import binascii
import wifi_credentials
import time

import lz_hub_db
from lz_hub_element_type import ELEMENT_TYPE
from lz_hub_dev_update import get_update_file_unsigned
import open_ssl_wrapper as osw
import uuid as u

TEST_CERTS_PATH         = './test_certs/'
LEN_PUB_KEY_PEM         = 279


class device_certbag:
    def __init__(self, uuid):
        self.uuid = uuid
        self.device_id_cert = None
        self.device_id_public_pem = None
        self.alias_id_cert = None

        db = lz_hub_db.connect()
        if db is None:
            print("Error: Failed to connect to lazarus database")
            return

        device_id_cert_buf, alias_id_cert_buf = lz_hub_db.get_device_certs(db, self.uuid)
        lz_hub_db.close(db)
        if device_id_cert_buf is None:
            print("ERROR: Failed to retrieve DeviceID certificate for UUID %s" %str(u.UUID(bytes=uuid)))
            return

        self.device_id_cert = osw.load_cert_from_buffer(device_id_cert_buf)
        if self.device_id_cert is not None:
            self.device_id_public_pem = osw.dump_publickey(self.device_id_cert.get_pubkey())
        else:
            print("ERROR: Failed to convert DeviceID buffer to cert")

        if alias_id_cert_buf is not None:
            self.alias_id_cert = osw.load_cert_from_buffer(alias_id_cert_buf)
            if self.alias_id_cert is None:
                print("ERROR: Failed to convert AliasID buffer to certificate")
        else:
            print("WARN: Failed to retrieve alias_id_cert (this is normal if device connects the first time)")


    def update_alias_id_cert(self, alias_id_buf, hub_cert):
        print("INFO: Verifying AliasID certificate chain with DeviceID and Hub cert..")
        alias_id_cert = osw.load_cert_from_buffer(alias_id_buf)
        trusted_certs = [hub_cert, self.device_id_cert]
        if not osw.verify_cert(trusted_certs, alias_id_cert):
            print("ERROR: Certificate chain could not be verified")
            return False
        print("INFO: Verification of certificate chain successful")

        print("INFO: Storing AliasID certificate..")
        try:
            db = lz_hub_db.connect()
            lz_hub_db.update_alias_id_cert(db, self.uuid, alias_id_buf)
            lz_hub_db.close(db)
        except Exception as e:
            print("ERROR: could not store AliasID certificate: %s" %str(e))
            return False

        self.alias_id_cert = alias_id_cert

        print("INFO: Successfully updated AliasID certificate")

        return True


    def reassociate_device_id_cert(self, cert_buffer, dev_auth_device, hub_cert, hub_sk):

        print("INFO: Reassociating DeviceID cert..")

        # Read DeviceID CSR from device
        # TODO static_symm could be sent inside certificate
        # device_id_csr_string = cert_buffer.decode('utf-8')

        # Read the DeviceID CSR
        device_id_csr = osw.load_csr_from_buffer(cert_buffer)
        if device_id_csr is None:
            print("Unable to load DeviceID CSR. Exit..")
            return False


        # dev_auth calculation
        dev_id_pub_key = osw.dump_publickey(device_id_csr.get_pubkey())

        # Calculate dev_symm from static_symm stored in hub. The certificate chain cannot be
        # verified at this point, as the device was just updated and has a new DeviceID. However
        # dev_symm proves that this is actually the device AND its running exactly the firmware
        # the hub issued
        dev_auth_calculated = self.__calculate_dev_auth(dev_id_pub_key)

        # Compare the sent dev_symm with the static_symm stored in the hub during initial
        # provisioning
        if dev_auth_device != dev_auth_calculated:
            print("ERROR: dev_auth mismatch. Refusing device_id certificate update")
            return False

        # Create a new, hub-signed DeviceID certificate with the extracted public DeviceID key
        self.device_id_cert = osw.create_cert_from_csr(device_id_csr, hub_sk, hub_cert, True)

        device_id_cert_buf = osw.dump_cert(self.device_id_cert)

        # Store the DeviceID certificate to be able to verify AliasID signed tickets
        db = lz_hub_db.connect()
        lz_hub_db.update_device_id_cert(db, self.uuid, device_id_cert_buf)
        lz_hub_db.close(db)

        # Update device_id public key
        self.device_id_public = self.device_id_cert.get_pubkey()

        print("INFO: Successfully updated DeviceID certificate")

        return True

    ###
    ### Private Functions
    ###

    def __calculate_dev_auth(self, device_id_public):

        print("INFO: Calculating dev_auth..")
        # Read stored static_symm
        db = lz_hub_db.connect()
        static_symm = lz_hub_db.get_static_symm(db, self.uuid)
        lz_hub_db.close(db)
        if static_symm is None:
            print("ERROR: Could not retrieve static_symm")
            return None

        # Read lz_core binary
        lz_core = get_update_file_unsigned(ELEMENT_TYPE.LZ_CORE_UPDATE)
        if lz_core is None:
            print("ERROR: Could not read lazarus core binary for dev_auth calculation")
            return None

        # Paper: Software Version M_x. This is the hashed current lz_core binary
        lz_core_digest = sha256(lz_core)
        core_auth_digest = lz_core_digest + self.uuid

        # core_auth = HMAC(core_auth_digest, static_symm)
        core_auth = hmac_sha256(core_auth_digest, static_symm)

        # dev_auth_digest = DeviceID | dev_uuid
        dev_auth_digest = device_id_public + (LEN_PUB_KEY_PEM-len(device_id_public) * b"\x00") + self.uuid

        # dev_auth = HMAC(dev_auth_digest, core_auth)
        dev_auth = hmac_sha256(dev_auth_digest, core_auth)

        return dev_auth



def hmac_sha256(message, key):
    return hmac.new(key, message, hashlib.sha256).digest()


def sha256(message):
    return hashlib.sha256(message).digest()


def print_data(data, info):
    try:
        print("%s: %s" %(info, "".join("{:02x} ".format(x) for x in data)))
    except Exception as e:
        print("WARN: Could not print data - %s" %str(e))

############################
########## TEST ############
############################

def test():

    # Read test data
    try:
        with open(TEST_CERTS_PATH + "hub_cert.pem", "rb") as cert_file:
            hub_cert = cert_file.read()
        with open(TEST_CERTS_PATH + "alias_id_cert.pem", "rb") as cert_file:
            alias_id_cert = cert_file.read()
        with open(TEST_CERTS_PATH + "hub_sk.pem", "rb") as cert_file:
            hub_sk = cert_file.read()
        with open(TEST_CERTS_PATH + "device_id_cert.pem", "rb") as cert_file:
            device_id_cert = cert_file.read()
        with open(TEST_CERTS_PATH + "static_symm", "rb") as cert_file:
            static_symm = cert_file.read()
        with open(TEST_CERTS_PATH + "dev_uuid", "rb") as cert_file:
            uuid = cert_file.read()
        with open(TEST_CERTS_PATH + "device_id_csr.pem", "rb") as cert_file:
            device_id_csr = cert_file.read()
    except Exception as e:
        print("Error opening certificate file: %s"
              % (str(e)))
        return None

    dev_auth = bytearray([  0x83,0x86,0x60,0xce,0x89,0x41,0x8d,0x39,
                            0xbe,0x52,0xb5,0x93,0x27,0xa1,0x5f,0x6d,
                            0x85,0x0e,0x8a,0x6b,0x09,0x6b,0xbc,0x1c,
                            0x4c,0xa8,0x62,0x87,0x46,0xc8,0x6e,0xbb])

    cb = device_certbag(uuid)

    device_id_cert = osw.load_cert_from_buffer(device_id_cert)
    hub_cert = osw.load_cert_from_buffer(hub_cert)
    trusted_certs = [hub_cert, device_id_cert]
    hub_sk = osw.load_privatekey_from_buffer(hub_sk)

    cb.update_alias_id_cert(alias_id_cert, trusted_certs)
    cb.reassociate_device_id_cert(device_id_csr, dev_auth, hub_cert, hub_sk)