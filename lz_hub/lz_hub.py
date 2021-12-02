#!/usr/bin/env python3

import socket
import ecdsa
import struct
from enum import IntEnum
import hashlib
from OpenSSL import crypto
import open_ssl_wrapper as osw
import argparse
import os
import wifi_credentials
from lz_hub_device_certbag import device_certbag
from lz_hub_certbag import hub_certbag
from lz_hub_dev_update import get_update_file
from lz_hub_element_type import ELEMENT_TYPE
import lz_hub_db
from ecdsa.util import sigencode_der, sigdecode_der
import uuid as u

MAX_DEFERRAL_TIME       = 1000*60*60

TCP_CMD_REQ_BACKEND_PK  = 0x4
TCP_CMD_ACK             = 0x3
TCP_CMD_NAK             = 0x2
TCP_CMD_TEST            = 0x1

LEN_WIFI_SSID           = 128
LEN_WIFI_PWD            = 64
LEN_WIFI_AUTH_METHOD    = 32
LEN_WIFI_IP             = 48

LEN_DEV_AUTH            = 32
LEN_DEV_UUID            = 16
LEN_PUB_KEY_PEM         = 279

LEN_SIGNED_AREA = 76 + LEN_DEV_UUID
LEN_SIGNATURE = 84
LEN_HDR = LEN_SIGNED_AREA + LEN_SIGNATURE

MAGICVAL                = (0x41495345)


def main():
    global wifi_credentials_file_name
    print("-------------------------- Backend server v0.1 -----------------------------")
    cert_path, wifi_credentials_file_name = parse_arguments()

    # Load wifi-credentials from file.
    wifi_params = wifi_credentials.load(wifi_credentials_file_name)
    if wifi_params is None:
        return 0

    # Load certificates
    hub_cb = hub_certbag(cert_path)

    if not hub_cb.load():
        print("ERROR: Could not load hub certificates. Exit..")
        return 0

    print("Waiting for connections..")

    # Establish connection
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((wifi_params['ip'], wifi_params['port']))
            except Exception as e:
                print("ERROR: Failed to bind socket to %s:%s - %s" %(wifi_params['ip'],
                    wifi_params['port'], str(e)))
                break
            s.listen()
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    # Receive data
                    try:
                        data = conn.recv(1024)
                    except Exception as e:
                        print("HUB: ERROR - %s" %str(e))
                        break
                    if not data:
                        break

                    handle_request(conn, data, hub_cb)

                    print("Packet evaluated. Waiting for new data..")
                    print("----------------------------------------")
                    print("")


def handle_request(conn, data, hub_cb):

    # Pre-unpack the element-type to see if it is an authenticated or unauthenticated packet
    try:
        element_type = struct.unpack('I', data[:4])[0]
        print("Received packet type %s, length = %d" %(ELEMENT_TYPE(element_type), len(data)))
    except Exception as e:
        print("Invalid packet type: %s. Abort" %str(e))
        return

    # DeviceID re-association is a special case
    if element_type == ELEMENT_TYPE.DEVICE_ID_REASSOC_REQ:
        handle_device_id_reassociation(conn, data, hub_cb)
    # An AliasID update or a CMD is unauthenticated
    elif element_type == ELEMENT_TYPE.ALIAS_ID or element_type == ELEMENT_TYPE.CMD:
        handle_unauthenticated_reqest(conn, data, hub_cb)
    # All other packets are authenticated
    else:
        handle_authenticated_reqest(conn, data, hub_cb)


def handle_unauthenticated_reqest(conn, data, hub_cb):

    print("Processing UNAUTHENTICATED packet..")
    len_hdr = 8+LEN_DEV_UUID
    try:
        element_type, payload_size, uuid = struct.unpack("II16s", data[:len_hdr])
        payload = struct.unpack("%ds" %payload_size, data[len_hdr:])[0]
    except Exception as e:
        print("Error unpacking data: %s" %str(e))
        conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_NAK))
        return

    if element_type == ELEMENT_TYPE.ALIAS_ID:
        print(str(u.UUID(bytes=uuid)))
        handle_alias_id_cert_update(conn, uuid, payload, hub_cb)
    elif element_type == ELEMENT_TYPE.CMD:
        handle_cmd(conn, uuid, payload)
    else:
        print("unknown command")

    return


def handle_cmd(conn, uuid,  payload):
    print("Received Command")

    if payload == TCP_CMD_REQ_BACKEND_PK:
        print("TCP_CMD TCP_CMD_REQ_BACKEND_PK")
        # TODO
        # The key format requests 0x4 as the first byte
        # first_byte = 0x4
        # backend_pk_str = ecdsa.VerifyingKey.to_string(hub_pk_ecdsa)

        # TODO send back key in correct authenticated format
    if payload == TCP_CMD_ACK:
        print("TCP_CMD_ACK")
    elif payload == TCP_CMD_NAK:
        print("TCP_CMD_NAK")
    elif payload == TCP_CMD_TEST:
        print("TCP_CMD_TEST")
    else:
        print("TCP_CMD_UNKNOWN")


def handle_authenticated_reqest(conn, data, hub_cb):

    print("Processing AUTHENTICATED packet..")

    try:
        signed_area, signature = struct.unpack("%ds%ds" %(LEN_SIGNED_AREA, LEN_SIGNATURE), data[:LEN_HDR])
        sig_len = int.from_bytes(signature[-4:], "little")
        signature = signature[:sig_len]
        element_type, payload_size, uuid, magic, nonce, digest = struct.unpack("II16sI32s32s", signed_area)
        payload = struct.unpack("%ds" %payload_size, data[LEN_HDR:])[0]
    except Exception as e:
        print("Error unpacking data: %s" %str(e))
        return

    # Load certificates from database
    device_cb = device_certbag(uuid)
    trusted_certs = [hub_cb.hub_cert, device_cb.device_id_cert]
    if not osw.verify_cert(trusted_certs, device_cb.alias_id_cert):
        print("ERROR: Certificate chain could not be verified")
        conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_NAK))
        return

    try:
        print("Verifying request with AliasID public key..")
        alias_id_pk_ecdsa = ecdsa.VerifyingKey.from_pem(osw.dump_publickey(device_cb.alias_id_cert.get_pubkey()))
        ret = alias_id_pk_ecdsa.verify(signature, signed_area, hashfunc=hashlib.sha256, sigdecode=sigdecode_der)
        if ret == True:
            print("Good signature!")
        else:
            print("ERROR: Bad signature. Drop packet")
            conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_NAK))
            return
    except Exception as e:
        print("ERROR: Could not verify signature: %s. Drop packet" %(str(e)))
        conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_NAK))
        return

    # Verify payload
    calculated_digest = hashlib.sha256(payload).digest()
    if calculated_digest != digest:
        print(f"ERROR: digest mismatch - {calculated_digest} vs. {digest}")
        conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_NAK))
        return

    print("Digest verification successful")

    # Handle request according to type
    if ((element_type == ELEMENT_TYPE.APP_UPDATE) or
        (element_type == ELEMENT_TYPE.UD_UPDATE) or
        (element_type == ELEMENT_TYPE.UM_UPDATE) or
        (element_type == ELEMENT_TYPE.LZ_CORE_UPDATE)):

        payload = get_update_file(element_type)
        if payload is None:
            print("ERROR: Failed to retrieve firmware update file on hub")
            conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_NAK))
            return

    elif element_type == ELEMENT_TYPE.BOOT_TICKET:

        payload = struct.pack("I", magic)

    elif element_type == ELEMENT_TYPE.DEFERRAL_TICKET:

        time_ms = get_deferral_time(struct.unpack("I", payload)[0])
        payload = struct.pack("I", time_ms)

    elif element_type == ELEMENT_TYPE.CONFIG_UPDATE:

        payload = get_nw_config()
        if payload is None:
            print("ERROR: Failed to retrieve firmware update file on hub")
            conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_NAK))
            return

    elif element_type == ELEMENT_TYPE.SENSOR_DATA:

        try:
            index, temp, humidity = struct.unpack("Iff", payload)
        except Exception as e:
            print("ERROR: Failed to unpack sensor data - %s" %str(e))
            conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_NAK))
            return
        print("INFO: UUID = %s" %str(u.UUID(bytes=uuid)))
        print("INFO: INDEX %d = TEMP: %f°C, HUMIDITY: %fpct" %(index, temp, humidity))
        db = lz_hub_db.connect()
        lz_hub_db.update_data(db, uuid, 1, index, temp, humidity)
        lz_hub_db.close(db)

        payload = payload = struct.pack("I", TCP_CMD_ACK)

    else:
        print("ERROR: Received unknown packet: %d" %element_type)
        print("Full packet: ")
        print(data)
        print("Abort")
        conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_NAK))
        return

    send_element(conn, magic, nonce, element_type, uuid, payload, hub_cb)


def handle_device_id_reassociation(conn, data, hub_cb):

    print("Processing AUTHENTICATED packet..")

    try:
        signed_area, signature = struct.unpack("%ds%ds" %(LEN_SIGNED_AREA, LEN_SIGNATURE), data[:LEN_HDR])
        element_type, payload_size, uuid, magic, nonce, digest = struct.unpack("II16sI32s32s", signed_area)
        payload = struct.unpack("%ds" %payload_size, data[LEN_HDR:])[0]
    except Exception as e:
        print("Error unpacking data: %s" %str(e))
        return

    # DO NOT verify the signature here, as we have a new DeviceID which must first be
    # validated using dev_auth

    # Verify payload
    calculated_digest = hashlib.sha256(payload).digest()
    if calculated_digest != digest:
        print("ERROR digest mismatch")
        conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_NAK))
        return

    print("Digest verification successful")

    # payload = enc(dev_uuid | dev_auth | DeviceID CSR)^hub_pub
    payload_decrypted = ecdh_decrypt(payload, hub_cb.hub_sk)

    device_id_csr_len = len(payload) - LEN_DEV_AUTH - LEN_DEV_UUID

    # TODO not necessary to pack in dev_uuid anymore
    (dev_uuid,
    dev_auth,
    csr_buffer) = struct.unpack('%ds%ds%ds' %(LEN_DEV_UUID, LEN_DEV_AUTH, device_id_csr_len),
        payload_decrypted)

    device_cb = device_certbag(uuid)
    if not device_cb.reassociate_device_id_cert(csr_buffer, dev_auth, hub_cb.hub_cert, hub_cb.hub_sk):
        print("ERROR: Unable to update and reassociate DeviceID certificate.")
        print("Cert: %s" %csr_buffer)
        conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_NAK))
        return

    # NOW the signature of the packet can be verified with the new device ID
    # TODO implement this

    # Send back the trust anchors structure
    device_id_cert = osw.dump_cert(device_cb.device_id_cert)
    if device_id_cert is None:
        print("ERROR: Could not convert certificate to raw format")
        return

    magic = MAGICVAL
    flags = 0
    # device_id_pub_key = bytearray(LEN_PUB_KEY)
    # code_auth_pub_key = bytearray(LEN_PUB_KEY)
    # hub_pub_key = bytearray(LEN_PUB_KEY)
    hub_cert_start = 0
    hub_cert_size = 0
    device_id_cert_start = 0
    device_id_cert_size = len(device_id_cert)
    cursor = hub_cert_start + hub_cert_size + device_id_cert_size
    cert_bag = device_id_cert + bytearray(4076 - device_id_cert_size)

    try:
        payload = struct.pack(
            # 'II76s76s76sHHHHI3848s',  # (TRUST_ANCHORS = 4096 Bytes)
            'IIHHHHI4076s',  # (TRUST_ANCHORS = 4096 Bytes)
            magic,
            flags,
            # device_id_pub_key,
            # code_auth_pub_key,
            # hub_pub_key,
            hub_cert_start,
            hub_cert_size,
            device_id_cert_start,
            device_id_cert_size,
            cursor,
            cert_bag)
    except Exception as e:
        print("Unable to pack trust anchors to raw-data: %s. Exit.." %str(e))
        return 0

    send_element(conn, MAGICVAL, nonce, ELEMENT_TYPE.CERTS_UPDATE, uuid, payload, hub_cb)


def get_deferral_time(time_ms):

    print("Requested time ms: %dms" %time_ms)
    if time_ms > MAX_DEFERRAL_TIME:
        time_ms = MAX_DEFERRAL_TIME
        print("Requested deferral time violating server policies. Reducing deferral time to "
            "%dms" %MAX_DEFERRAL_TIME)

    return time_ms


def get_nw_config():

    params = wifi_credentials.load(wifi_credentials_file_name)
    if params is None:
        return 0

    img_meta_data = bytearray(64)
    dev_symm = bytearray(140)
    padding = bytearray(3612)

    magic_nw_data = MAGICVAL
    wifi_auth_method = bytearray(LEN_WIFI_AUTH_METHOD)
    wifi_pwd = bytearray(params['pwd'], 'utf-8') + bytearray(LEN_WIFI_PWD - len(params['pwd']))
    wifi_ssid = bytearray(params['ssid'], 'utf-8') + bytearray(LEN_WIFI_SSID - len(params['ssid']))
    server_ip_addr = bytearray(params['ip'], 'utf-8') + bytearray(LEN_WIFI_IP -  len(params['ip']))
    server_port = params['port']

     # Create the trust anchors c structure
    try:
        config_data = struct.pack(
            '64s140sI128s64s32s48sI3612s',
            # IMG_META_DATA (64s = 64 Bytes)
            img_meta_data,
            # DEV_SYM_INFO (140s = 140 Bytes)
            dev_symm,
            # NW_DATA_INFO (I128s64s32s48sI = 278 Bytes)
            magic_nw_data,
            wifi_ssid,
            wifi_pwd,
            wifi_auth_method,
            server_ip_addr,
            server_port,
            padding)
    except Exception as e:
        print("Unable to pack network data configuration: %s. Exit.." %str(e))
        return None

    return config_data


def send_element(conn, magic, nonce, element_type, uuid, payload, hub_cb):

    # Calculate digest and size of payload
    payload_size = len(payload)
    digest = hashlib.sha256(payload).digest()

    # Create element header
    try:
        hdr_data = struct.pack('II16sI32s32s',  element_type,
                                                payload_size,
                                                uuid,
                                                magic,
                                                nonce,
                                                digest,
                                                )
    except Exception as e:
        print("ERROR: failed to create header: %s" %str(e))
        return

    # Append signature to header
    hdr_sig = hub_cb.hub_sk_ecdsa.sign(hdr_data, hashfunc=hashlib.sha256, sigencode=sigencode_der)
    if len(hdr_sig) > LEN_SIGNATURE:
        print(f"ERROR: signature too long ({len(hdr_sig)} > {LEN_SIGNATURE})")
        return
    print(f"Length of the signature: {len(hdr_sig)}")
    # We now need to make the signature to a byte block of length 84
    hdr_sig = hdr_sig + (b"\x00" * (LEN_SIGNATURE - len(hdr_sig) - 4)) + int.to_bytes(len(hdr_sig), 4, "little")



    print_tcp_element_info(payload_size, nonce, element_type, digest, hdr_sig)

    data = hdr_data + hdr_sig + payload

    print("Sending %s (total %d bytes, payload %d bytes)"
        %(ELEMENT_TYPE(element_type), len(data), len(payload)))
    try:
        conn.sendall(data)
    except Exception as e:
        print("ERROR: failed to send data: %s" %str(e))
        return


def handle_alias_id_cert_update(conn, uuid, cert_buffer, hub_cb):

    print("INFO: Updating AliasID for UUID %s" %str(u.UUID(bytes=uuid)))
    device_cb = device_certbag(uuid)
    if not device_cb.update_alias_id_cert(cert_buffer, hub_cb.hub_cert):
        print("ERROR: Unable to update AliasID certificate.")
        conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_NAK))
        return

    print("Send back Response ACK..")
    conn.sendall(struct.pack('II16sI', ELEMENT_TYPE.CMD, 4, uuid, TCP_CMD_ACK))


# TODO at the moment just a dummy Implement this
def ecdh_decrypt(payload, hub_cb):
    return payload


### Helper methods ###


def print_tcp_element_info(payload_size, nonce, element_type, digest, signature):

    print("Payload size:    %d (0x%x) bytes" %(payload_size, payload_size))
    print("Nonce:           %s" %("".join("{:02x}".format(x) for x in nonce)))
    print("Type:            %s" %ELEMENT_TYPE(element_type)) # TODO readable
    print("Digest:          %s" %("".join("{:02x}".format(x) for x in digest)))
    print("Signature:       %s" %("".join("{:02x}".format(x) for x in signature)))


def parse_arguments():

    parser = argparse.ArgumentParser()
    parser.add_argument("cert_path", help="The path where the backend and the code authentification"
        " certificates are located")
    parser.add_argument("wifi_credentials_file", help = 'The filename including its path of the '
        'file with the wifi-credentials.\n'
        'The File must look like this:\n'
        'ssid=	"my-network-ssid"\n'
        'ip="192.168.0.1"\n'
        'pwd= "mypassword123"\n'
        'port=   "65433"\n')
    args = parser.parse_args()
    cert_path = args.cert_path.rstrip("/")
    wifi_credentials_file_name = args.wifi_credentials_file
    print("Loading certs from %s"  %os.path.abspath(cert_path))
    print("Loading wifi-credentials file %s" %os.path.abspath(wifi_credentials_file_name))

    return cert_path, wifi_credentials_file_name


### main ###


if __name__ == "__main__":
    main()


# TODO real unit test framework
##############################################
############### TEST ONLY ####################
##############################################

def test():

    hub_cb = hub_certbag("./certificates")
    hub_cb.load()

    try:
        with open("unit_test/lz_hub_test_requests/req0", "rb") as f:
            data = f.read()
    except Exception as e:
        print("ERROR: %s" %str(e))

    handle_request(None, data, hub_cb)
