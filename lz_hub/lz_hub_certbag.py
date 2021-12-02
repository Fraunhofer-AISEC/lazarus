#!/usr/bin/env python3

import ecdsa
import struct
import hashlib
import OpenSSL
import open_ssl_wrapper as osw

count = 0

class hub_certbag:
    def __init__(self, cert_path):
        self.cert_path = cert_path
        self.hub_cert = None
        self.hub_sk = None
        self.hub_sk_ecdsa = None

    def load(self):
        self.hub_cert = osw.load_cert(self.cert_path + "/hub_cert.pem")
        if self.hub_cert is None:
            return False
        self.hub_sk = osw.load_privatekey(self.cert_path + "/hub_sk.pem")
        if self.hub_sk is not None:
            tmp = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, self.hub_sk)
            self.hub_sk_ecdsa = ecdsa.SigningKey.from_der(tmp, hashfunc=hashlib.sha256)
        else:
            return False
        return True


    def print_pub_key(self, cert):
        tmp = ecdsa.VerifyingKey.from_pem(osw.dump_publickey(cert.get_pubkey()))
        pubkey = struct.pack('B64s', 0x4, ecdsa.VerifyingKey.to_string(tmp))
        print("key: %s" %("".join("{:02x} ".format(x) for x in pubkey[:20])))


def print_data(data, info):
    try:
        print("%s: %s" %(info, "".join("{:02x} ".format(x) for x in data)))
    except Exception as e:
        print("WARN: Could not print data - %s" %str(e))


def test():
    cert_path = "/home/simon/repos/lazarus/lz_hub/certificates"

    cb = hub_certbag(cert_path)
    cb.load()