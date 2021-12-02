import sys
import ecdsa
import hashlib
import OpenSSL
from OpenSSL import crypto
import open_ssl_wrapper as osw
import os
import argparse
import struct
import time
from ecdsa.util import sigencode_der

HEADER_SIZE         = 0x800
LEN_SIGNATURE = 84

def main():
    print("")
    print("Creating signed code file..")

    # Parse the mandatory arguments of the script
    args = parse_arguments()

    # Read hub certificate and private key TODO change file paths
    hub_cert = osw.load_cert(args.cert_path + "/hub_cert.pem")
    if hub_cert is None:
        print("Unable to load all certificates. Exit..")
        return 1
    hub_sk = osw.load_privatekey(args.cert_path + "/hub_sk.pem") # TODO password?
    if hub_sk is None:
        print("Unable to load all certificates. Exit..")
        return 1

    # Read code signing certificate and private key TODO change file paths
    code_auth_cert = osw.load_cert(args.cert_path + "/code_auth_cert.pem")
    if code_auth_cert is None:
        print("Unable to load all certificates. Exit..")
        return 1
    code_auth_sk_ossl = osw.load_privatekey(args.cert_path+ "/code_auth_sk.pem")
    if code_auth_sk_ossl is None:
        print("Unable to load all certificates. Exit..")
        return 1

    # Convert them into objects of the ECDSA library which operate with the raw format
    code_auth_sk_tmp = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, code_auth_sk_ossl)
    code_auth_sk_ecdsa = ecdsa.SigningKey.from_der(code_auth_sk_tmp, hashfunc=hashlib.sha256)

    # Create signed code files
    return create_signed_code_file(args.in_file, args.buildno_file, code_auth_sk_ecdsa, args.out_file, args.c, args.e)

def create_signed_code_file(code_file_name, build_file_name, code_auth_sk_ecdsa, out_file, is_core, is_erased):

    # Check if build number file exists, if not, create it
    if not os.path.isfile(build_file_name):
        build_no = 0
        try:
            with open(build_file_name, "w") as build_file:
                build_file.write(str(build_no))
        except Exception as e:
            print("Error: failed to open build file %s for writing with error %s" %(os.path.abspath(build_file_name), str(e)))
            return 1
    else:
        # Read build number from include/buildno.h
        try:
            with open(build_file_name, "r") as build_file:
                build_no = int(build_file.read())
        except Exception as e:
            print("Error: failed to open build file %s with error %s" %(os.path.abspath(build_file_name), str(e)))
            return 1

        # Increment build number (optional)
        build_no = build_no + 1

        try:
            with open(build_file_name, "w") as build_file:
                build_file.write(str(build_no))
        except Exception as e:
            print("Error: failed to open build file %s for writing with error %s" %(os.path.abspath(build_file_name), str(e)))
            return 1

    # Hash the code file
    try:
        with open(code_file_name, "rb") as code_file:
            code_file_content = code_file.read()
    except Exception as e:
        print("Error: failed to open code file %s with error %s" %(os.path.abspath(code_file, str(e))))
        return 1

    code_file_hash = hashlib.sha256(code_file_content)

    # Create header structure and fill with data
    magic = 0x41495345
    header_size = HEADER_SIZE
    name = bytearray(os.path.splitext(os.path.basename(code_file_name))[0], 'utf-8')
    version = build_no
    image_size = len(code_file_content)
    issue_time = int(time.time())
    digest = code_file_hash.digest()

    # Check length of name and pad name with zeros
    if len(name) > 31:
        print("Error: Length of binary name too long (max is 31). Abort")
        return 1
    name = name + bytearray(32 - len(name))

    # The header WITHOUT the signature
    hdr_data = struct.pack('2I32sIIq32s', magic,
                                        header_size,
                                        name,
                                        version,
                                        image_size,
                                        issue_time,
                                        digest,
                                        )

    # Sign the header with the code authentication key
    hdr_sig = code_auth_sk_ecdsa.sign(hdr_data, hashfunc=hashlib.sha256, sigencode=sigencode_der)
    hdr_sig = hdr_sig + (b"\x00" * (LEN_SIGNATURE - len(hdr_sig) - 4)) + int.to_bytes(len(hdr_sig), 4, "little")

    # Print binary info
    print("")
    print("Name:            %s" %name.decode('utf-8'))
    print("Size:            %d (0x%x) bytes" %(image_size, image_size))
    print("Version:         %d" %version)
    print("Issued (UTC):    0x%08x, %s" %(issue_time, time.asctime(time.gmtime(issue_time))))
    print("Digest:          %s" %code_file_hash.hexdigest())
    print("Signature:       %s" %("".join("{:02x}".format(x) for x in hdr_sig)))

    # Copy the signature into PIMG_HDR signature field
    hdr = hdr_data + hdr_sig

    # The header page in the flash has a size of 0x800. The actual header is smaller.
    # Fill the rest of the header with zeros up to 0x800
    size_fill = 0x800 - len(hdr)
    hdr = hdr + bytearray(size_fill)

    # Create final binary, consisting of header and code file. The lazarus core bianry has a
    # different format and therefore must be flashed differently. If the flash was erased,
    # the Dice++ Datastore is included in the lazarus core binary
    if is_core and is_erased:
        out_code_file_content = bytearray(bytearray(0x7800) + code_file_content[0x0:0x800] + hdr + code_file_content[0x1000:])
    elif is_core:
        out_code_file_content = bytearray(code_file_content[0x0:0x800] + hdr + code_file_content[0x1000:])
    else:
        out_code_file_content = bytearray(hdr + code_file_content)

    try:
        with open(out_file, "wb") as out_code_file:
            out_code_file.write(out_code_file_content)
    except Exception as e:
        print("Failed to write signed binary to file: %s" %str(e))
        return 1

    print("---")
    print("Successfully created signed code file %s" %os.path.basename(out_file))

    return 0


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("in_file", help="The binary file to be signed")
    parser.add_argument("buildno_file", help="The file containing the build number")
    parser.add_argument("out_file", help="Name of the signed output binary")
    parser.add_argument("cert_path", help="The path where the backend and the code authentification certificates are located")
    parser.add_argument("-c", action='store_true', help="flag to indicate that binary is lazarus core")
    parser.add_argument("-e", action='store_true', help="flag to indicate that flash was erased and datastore needs to be included")

    args = parser.parse_args()
    args.cert_path = args.cert_path.rstrip("/")

    print("Specified input file: %s" %os.path.abspath(args.in_file))
    print("Specified buildno file: %s" %os.path.abspath(args.buildno_file))
    print("Specified output file: %s" %os.path.abspath(args.out_file))
    print("Specified cert path: %s" %os.path.abspath(args.cert_path))

    return args


if __name__ == "__main__":
    ret = main()
    sys.exit(ret)
