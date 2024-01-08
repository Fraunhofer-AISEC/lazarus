#!/usr/bin/env python3

import sys
sys.path.append('protobuf')
import socket
import ecdsa
import struct
import traceback
from enum import IntEnum
import hashlib
from OpenSSL import crypto
import open_ssl_wrapper as osw
import argparse
import os
import wifi_credentials
from lz_hub_device_certbag import device_certbag
from lz_hub_certbag import hub_certbag
from lz_hub_device import get_device
import lz_hub_db
from ecdsa.util import sigencode_der, sigdecode_der
import uuid as u
import hubrequest_pb2
import hubresponse_pb2
import bootticket_request_pb2
import bootticket_response_pb2
import google.protobuf.message
import time
from threading import Thread

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


class HubException(Exception):
    pass


def receive_loop(conn, hub_cb):
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
    conn.close()

def main():
    global wifi_credentials_file_name
    print("-------------------------- Backend server v0.1 -----------------------------")
    cert_path, wifi_credentials_file_name = parse_arguments()

    # Connect to database and create all non-existing tables
    db = lz_hub_db.connect()
    db.close()

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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((wifi_params['ip'], wifi_params['port']))
        except Exception as e:
            print("ERROR: Failed to bind socket to %s:%s - %s" %(wifi_params['ip'],
                wifi_params['port'], str(e)))
            return
        s.listen(10)
        while True:
            conn, addr = s.accept()

            print('Connected by', addr)
            thread = Thread(target = receive_loop, args = (conn, hub_cb))
            thread.start()


def handle_framing(message):
    if len(message) < 2:
        raise HubException("Invalid framing (Received less than 2 bytes)")

    num_bytes = int.from_bytes(message[:2], "big")
    expected_bytes = len(message) - 2

    if expected_bytes != num_bytes:
        raise HubException("Invalid framing. Header announced {} bytes, but got {} bytes"
                           .format(num_bytes, expected_bytes))

    return message[2:]


def has_signature(request):
    # All messages are signed except of the Alias ID and reassociate request
    payload = request.WhichOneof('payload')
    return payload != 'aliasid' and payload != 'reassocDevice'


def handle_protobuf_message(conn, message, hub_cb):

    signed_request = hubrequest_pb2.SignedHubRequestMessage()
    request = hubrequest_pb2.HubRequestMessage()
    try:
        message = handle_framing(message)
        signed_request.ParseFromString(message)
        request.ParseFromString(signed_request.payload)
    except HubException as e:
        print("ERROR: Failed to parse incoming protobuf message: %s." %str(e))
        return
    except google.protobuf.message.DecodeError:
        print("ERROR: Failed to parse incoming protobuf message: Invalid format.")
        return

    # Signed Request: uuid | payload{ nonce | magic | payload } | signature
    uuid = signed_request.uuid
    signature = signed_request.signature
    payload = signed_request.payload

    # Update IP address in database
    update_ip(conn, uuid)

    print("Request type is %s" %(request.WhichOneof('payload')))

    if has_signature(request):
        signature_ok = check_signature(hub_cb, uuid, signature, payload)
        if not signature_ok:
            print("ERROR: Could not verify signature of incoming message type %s" %request.WhichOneof('payload'))
            return

    print("Protobuf type is " + str(request.WhichOneof('payload')))
    try:
        if request.WhichOneof('payload') == 'aliasid':
            handle_alias_id(conn, uuid, request, hub_cb)
        elif request.WhichOneof('payload') == 'bootTicket':
            handle_boot_ticket(conn, uuid, request, hub_cb)
        elif request.WhichOneof('payload') == 'awdt':
            handle_deferral_ticket(conn, uuid, request, hub_cb)
        elif request.WhichOneof('payload') == 'sensorData':
            handle_sensor_data(conn, uuid, request, hub_cb)
        elif request.WhichOneof('payload') == 'fwUpdate':
            handle_fw_update(conn, uuid, request, hub_cb)
        elif request.WhichOneof('payload') == 'reassocDevice':
            handle_reassoc_device(conn, uuid, request, hub_cb)
        elif request.WhichOneof('payload') == 'checkForUpdate':
            handle_check_for_update(conn, uuid, request, hub_cb)
        elif request.WhichOneof('payload') == 'userInput':
            handle_check_for_user_input(conn, uuid, request, hub_cb)
        else:
            raise HubException("Type of protobuf message is unknown")
    except HubException as e:
        print("ERROR:", str(e))
        print("Send back NAK response...")
        send_signed_nak_response(conn, hub_cb)


def handle_alias_id(conn, uuid, request, hub_cb):

    certificate = request.aliasid.certificate
    handle_alias_id_cert_update(conn, uuid, certificate, hub_cb)


def handle_boot_ticket(conn, uuid, request, hub_cb):

    print("Processing BOOT_TICKET packet..")

    response = get_device(uuid).get_boot_ticket_response(request.nonce, hub_cb)

    print("Send back Response..")
    type = hubresponse_pb2.SignedHubResponse.Type.BOOTTICKET
    send_signed_response(conn, type, response, hub_cb)


def update_ip(conn, uuid):

    ip, port = conn.getpeername()

    db = lz_hub_db.connect()
    if db:
        lz_hub_db.update_ip(db, uuid, ip, port)
        lz_hub_db.close(db)


def handle_deferral_ticket(conn, uuid, request, hub_cb):
    print("Processing DEFERRAL_TICKET packet..")

    response = hubresponse_pb2.HubResponseAwdtRefresh()
    response.nonce = request.nonce
    response.timeMs = request.awdt.timeMs

    db = lz_hub_db.connect()
    if db:
        lz_hub_db.update_awdt_period(db, uuid, response.timeMs / 1000)
        lz_hub_db.close(db)

    print("Send back Response..")
    type = hubresponse_pb2.SignedHubResponse.Type.AWDT
    send_signed_response(conn, type, response, hub_cb)


def handle_sensor_data(conn, uuid, request, hub_cb):
    print("Processing SENSOR_DATA packet..")

    temp = request.sensorData.temperature
    index = request.sensorData.index
    humidity = request.sensorData.humidity

    print("INFO: UUID = %s" %str(u.UUID(bytes=uuid)))
    print("INFO: INDEX %d = TEMP: %f°C, HUMIDITY: %fpct" %(index, temp, humidity))
    db = lz_hub_db.connect()
    if db:
        lz_hub_db.update_data(db, uuid, 1, index, temp, humidity)
        lz_hub_db.close(db)

        print("Send back Response..")
        response = hubresponse_pb2.HubResponseSensorData()
        type = hubresponse_pb2.SignedHubResponse.Type.SENSORDATA
        send_signed_response(conn, type, response, hub_cb)


def get_update_payload(uuid, update_type):
    if update_type == "config":
        return get_nw_config()

    payload = get_device(uuid).get_update_payload(update_type)
    if payload is None:
        raise HubException("Failed to retrieve firmware update file on hub")

    return payload


def handle_fw_update(conn, uuid, request, hub_cb):
    print("Processing FW_UPDATE packet..")

    # Signal that update is in progress now
    db = lz_hub_db.connect()
    if db:
        lz_hub_db.set_update_in_progress(db, uuid, 1)
        lz_hub_db.close(db)

    component = request.fwUpdate.type
    payload = get_update_payload(uuid, component)

    print("Send back Response..")
    response = hubresponse_pb2.HubResponseUpdate()
    response.nonce = request.nonce
    response.payloadNumBytes = len(payload)
    type = hubresponse_pb2.SignedHubResponse.Type.FWUPDATE
    send_signed_response_with_payload(conn, type, response, payload, hub_cb)

    # Determine version of sent payload and write to database
    _, version, _ = get_device(uuid).get_update_version(component)
    print(f"Version of \"{component}\" binary is {version}. Write version to database..")
    db = lz_hub_db.connect()
    if db:
        lz_hub_db.insert_or_update_version(db, uuid, request.fwUpdate.type, version)
        lz_hub_db.close(db)

    print("Finished FW_UPDATE process")


def handle_reassoc_device(conn, uuid, request, hub_cb):
    print("Processing REASSOCIATE packet..")

    uuid = request.reassocDevice.uuid
    auth = request.reassocDevice.auth
    dev_id_cert = request.reassocDevice.deviceIdCert

    device_cb = device_certbag(uuid)
    if not device_cb.reassociate_device_id_cert(dev_id_cert, auth, hub_cb.hub_cert, hub_cb.hub_sk):
        print("ERROR: Unable to update and reassociate DeviceID certificate.")
        print("Cert: %s" %dev_id_cert)
        raise HubException("Device reassociation failed")

    # NOW the signature of the packet can be verified with the new device ID
    # TODO implement this

    # Send back the trust anchors structure
    device_id_cert = osw.dump_cert(device_cb.device_id_cert)
    if device_id_cert is None:
        raise HubException("Could not convert certificate to raw format")

    print("Creating trust anchor structure")
    trust_anchor = create_trust_anchor(device_id_cert)

    print("Send back Response..")
    response = hubresponse_pb2.HubResponseUpdate()
    response.nonce = request.nonce
    response.payloadNumBytes = len(trust_anchor)
    type = hubresponse_pb2.SignedHubResponse.Type.REASSOC
    send_signed_response_with_payload(conn, type, response, trust_anchor, hub_cb)


def handle_check_for_update(conn, uuid, request, hub_cb):

    print("Processing CHECK_FOR_UPDATE packet..")

    response = hubresponse_pb2.HubResponseCheckForUpdate()
    response.nonce = request.nonce

    for component in request.checkForUpdate.components:
        print("Determine newest version of {}".format(component))
        payload = get_update_payload(uuid, component)
        name, newestVersion, issueTime = get_device(uuid).get_update_version(component)

        version_info = response.components.add()
        version_info.name = name
        version_info.newestVersion = newestVersion
        version_info.issueTime = issueTime

    print("Send back Response..")
    type = hubresponse_pb2.SignedHubResponse.Type.CHECKFORUPDATE
    send_signed_response(conn, type, response, hub_cb)

def handle_check_for_user_input(conn, uuid, request, hub_cb):

    print("Processing USER_INPUT packet")

    response = hubresponse_pb2.HubResponseUserInput()

    # Access database to check for new requests
    db = lz_hub_db.connect()
    if db:
        user_input = lz_hub_db.get_user_input(db, uuid)
        if user_input != "":
            lz_hub_db.clear_user_input(db, uuid)
            print("Got new user input: %s" %user_input)
            response.available = True
        else:
            print("No user input available")
            response.available = False

        lz_hub_db.close(db)
        response.userInput = bytes(user_input, 'utf-8')

    # Send back response
    print("Send back Response..")
    type = hubresponse_pb2.SignedHubResponse.Type.USERINPUT
    send_signed_response(conn, type, response, hub_cb)


def create_trust_anchor(device_id_cert):
    magic = MAGICVAL
    hub_cert_start = 0
    hub_cert_size = 0
    device_id_cert_start = 0
    device_id_cert_size = len(device_id_cert)
    cursor = hub_cert_start + hub_cert_size + device_id_cert_size
    cert_bag = device_id_cert + bytearray(3240 - device_id_cert_size)
    device_id_pub_key = bytearray(279)
    code_auth_pub_key = bytearray(279)
    hub_pub_key = bytearray(279)

    try:
        payload = struct.pack(
            'I279s279s279sHHHHI3240s',  # (TRUST_ANCHORS = 4096 Bytes)
            magic,
            device_id_pub_key,
            code_auth_pub_key,
            hub_pub_key,
            hub_cert_start,
            hub_cert_size,
            device_id_cert_start,
            device_id_cert_size,
            cursor,
            cert_bag)
    except Exception as e:
        print("Unable to pack trust anchors to raw-data: %s. Exit.." %str(e))
        return 0

    return payload


def check_signature(hub_cb, uuid, signature, payload):

    # Load certificates from database
    device_cb = device_certbag(uuid)
    trusted_certs = [hub_cb.hub_cert, device_cb.device_id_cert]
    if not osw.verify_cert(trusted_certs, device_cb.alias_id_cert):
        print("ERROR: Certificate chain could not be verified")
        return False

    try:
        print("Verifying request with AliasID public key..")
        alias_id_pk_ecdsa = ecdsa.VerifyingKey.from_pem(osw.dump_publickey(device_cb.alias_id_cert.get_pubkey()))
        ret = alias_id_pk_ecdsa.verify(signature, payload, hashfunc=hashlib.sha256, sigdecode=sigdecode_der)
        if ret:
            print("Good signature!")
        else:
            print("ERROR: Bad signature. Drop packet")
            return False
    except Exception as e:
        print("ERROR: Could not verify signature: %s. Drop packet" %(str(e)))
        return False

    print("Digest verification successful")
    return True


def handle_request(conn, data, hub_cb):
    try:
        handle_protobuf_message(conn, data, hub_cb)
    except Exception as e:
        print("Unhandled exception while processing incoming message")
        print(traceback.format_exc())


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
            '64s52sI128s64s32s48sI3700s',
            # IMG_META_DATA (64s = 64 Bytes)
            img_meta_data,
            # DEV_SYM_INFO (52s = 52 Bytes)
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


def prepend_frame_header(message):
    payload_len = len(message)
    header = payload_len.to_bytes(2, byteorder='big')
    return header + message


def handle_alias_id_cert_update(conn, uuid, cert_buffer, hub_cb):

    response = hubresponse_pb2.HubResponseAliasId()

    print("INFO: Updating AliasID for UUID %s" %str(u.UUID(bytes=uuid)))
    device_cb = device_certbag(uuid)
    if device_cb.update_alias_id_cert(cert_buffer, hub_cb.hub_cert):
        print("Send back ACK response...")
        type = hubresponse_pb2.SignedHubResponse.Type.ALIASID
        send_signed_response(conn, type, response, hub_cb)
    else:
        raise HubException("Unable to update AliasID certificate")


def send_signed_response_with_payload(conn, type, response, payload, hub_cb):
    send_signed_response(conn, type, response, hub_cb)

    time.sleep(2.5)
    try:
        conn.sendall(payload)
    except Exception as e:
        raise HubException("Failed to send response payload ({})".format(e))


def send_signed_response(conn, type, response_payload, hub_cb):
    signed_response = hubresponse_pb2.SignedHubResponse()
    signed_response.status = hubresponse_pb2.SignedHubResponse.Status.ACK
    signed_response.payload = response_payload.SerializeToString()
    signed_response.type = type

    # Append signature to header
    signed_response.signature = hub_cb.hub_sk_ecdsa.sign(
        signed_response.payload,
        hashfunc=hashlib.sha256,
        sigencode=sigencode_der)

    response_bytes = signed_response.SerializeToString()
    response_bytes = prepend_frame_header(response_bytes)
    try:
        conn.sendall(response_bytes)
    except Exception as e:
        raise HubException("Failed to send response message ({})".format(e))


def send_signed_nak_response(conn, hub_cb):
    signed_response = hubresponse_pb2.SignedHubResponse()
    signed_response.status = hubresponse_pb2.SignedHubResponse.Status.NAK

    response_bytes = signed_response.SerializeToString()
    response_bytes = prepend_frame_header(response_bytes)
    try:
        conn.sendall(response_bytes)
    except Exception as e:
        raise HubException("Failed to send NAK response message ({})".format(e))


# TODO at the moment just a dummy Implement this
def ecdh_decrypt(payload, hub_cb):
    return payload


### Helper methods ###

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
