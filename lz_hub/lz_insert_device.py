import sys
import ecdsa
import open_ssl_wrapper as osw
import os
import argparse
import struct
import wifi_credentials
import lz_hub_db
from OpenSSL import crypto
from dataclasses import astuple, dataclass


def main():
    dev_uuid = bytearray.fromhex(input("dev_uuid: "))
    dev_name = input("dev_name: ")
    dev_class = input("dev_class: ")
    device_id_cert = input("device_id_cert: ") + "\n"
    while "END" not in device_id_cert:
        device_id_cert += input() + "\n"

    static_symm = bytearray.fromhex(input("static_symm: "))

    db = lz_hub_db.connect()
    if not lz_hub_db.insert_device(db, dev_uuid, dev_name, dev_class, device_id_cert, static_symm):
        print("ERROR: Failed to store device in database. Exit..")
        return 1
    lz_hub_db.close(db)

    return 0


if __name__ == "__main__":
    ret = main()
    sys.exit(ret)
