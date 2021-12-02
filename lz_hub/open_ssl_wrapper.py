from OpenSSL import crypto
import sys

def dump_publickey(key):
    return crypto.dump_publickey(crypto.FILETYPE_PEM, key)


def dump_privatekey(key):
    return crypto.dump_privatekey(crypto.FILETYPE_PEM, key)


def dump_cert(cert):
    try:
        buffer = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    except Exception as e:
        print("ERROR: Could not dump certificate - %s" %str(e))
        return None
    return buffer


def load_privatekey_from_buffer(buf):
    try:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, buf)
    except Exception as e:
        print("Error getting private key: %s" %str(e))
        return None

    return key


def load_privatekey(name):
    try:
        f = open(name, "r")
    except Exception as e:
        print("Error opening private key file '%s': %s"
              % (name, str(e)))
        return None

    buf = f.read()
    f.close()
    try:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, buf)
    except Exception as e:
        print("Error loading private key: %s"
              % (str(e)))
        return None
    return key


def load_cert_from_buffer(buf):
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, buf)
    except Exception as e:
        print("Error loading certificate: %s"
              % (str(e)))
        return None
    return cert


def load_cert(name):
    try:
        f = open(name)
    except Exception as e:
        print("Error opening certificate file '%s': %s"
              % (name, str(e)))
        return None
    buf = f.read()
    f.close()
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, buf)

    except Exception as e:
        print("Error loading certificate: %s"
              % (str(e)))
        return None
    return cert


def store_cert_buffer(cert_buffer, filename):
    try:
         with open(filename, "wb") as file:
             file.write(cert_buffer)
    except Exception as e:
        print("Error storing certificate buffer: %s" % (str(e)))


def store_cert(cert, filename):
    store_cert_buffer(dump_cert(cert), filename)


def print_privatekey(privatekey):
    print(crypto.dump_privatekey(crypto.FILETYPE_PEM, privatekey).decode("utf-8"))


def print_cert_info(cert):
    print(crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey()).decode("utf-8"))

    subject = cert.get_subject()
    print(subject)

    valid = cert.get_notAfter().decode("utf-8")
    print("valid until %s" %valid)

# """
# TODO Check DeviceID
# """
def verify_cert(trusted_certs, cert_to_verify):

    try:
        store = crypto.X509Store()

        for cert in trusted_certs:
            store.add_cert(cert)

        store = crypto.X509StoreContext(store, cert_to_verify)

        # Verify the certificate, throws exception if not successful
        store.verify_certificate()

        return True

    except Exception as e:
        print("Error verifying certificate: %s" %str(e))
        return False

def create_cert_from_csr(csr, ca_sk, ca_cert, isCA):
    cert = crypto.X509()
    cert.set_version(0x2) # TODO take it from CSR
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())

    if isCA:
        ca_extension = b"CA:TRUE"
    else:
        ca_extension = b"CA:FALSE"

    cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, ca_extension),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert)
    ])

    cert.sign(ca_sk, 'sha256')

    return cert


def load_csr_from_buffer(buf):
    try:
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, buf)
    except Exception as e:
        print("Error: Unable to load CSR from buffer: %s" %str(e))
        return None
    return csr


def load_csr(filename):
    try:
         with open(filename, "r") as file:
             buf = file.read()
    except Exception as e:
        print("Error loading CSR from file: %s" % (str(e)))
        return None

    return crypto.load_certificate_request(crypto.FILETYPE_PEM, buf)


def dump_csr(csr):
    try:
        dumped_csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    except Exception as e:
        print("ERROR: Failed to dump certificate - %s" %str(e))
        return None
    return dumped_csr


def store_csr_buffer(csr_buffer, filename):
    try:
         with open(filename, "wb") as file:
             file.write(csr_buffer)
    except Exception as e:
        print("Error storing certificate buffer: %s" % (str(e)))
        return False
    return True


def store_csr(csr, filename):
    dumped_csr = dump_csr(csr)
    if dumped_csr is None:
        return False
    return store_csr_buffer(dump_csr(csr), filename)