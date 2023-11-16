from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import binascii


def sign(message, key):
    f=open("message","wb")
    f.write(message)
    f.close()
    key = RSA.import_key(open(key).read())
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    hashfile=open("hash","wb")
    hashfile.write(h.digest())
    hashfile.close()
    sigfile=open("signature","wb")
    sigfile.write(signature)
    sigfile.close()
    print("Hash to sign: ")
    print(h.hexdigest())
    print("\n")
    
    return signature

def hash(message):
    h = SHA256.new(message)
    return h.digest()

def verify(message, key, signature):
    key = RSA.import_key(open('update-linux-sign-pub-4096.der').read())
    print("Key: ")
    print(key)
    print("\n")
    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature)
        print("The signature is valid.")
        return True
    except (ValueError, TypeError):
        print("The signature is not valid.")
        return False


def Main():
    message = b'\x00\x01\x02\x03'
    keyname="update-linux-sign-private-4096.pem"
    signature=sign(message, keyname)
    print("Signature: ")
    print(binascii.hexlify(signature))
    print("\n")


    
if __name__ == '__main__':
    Main()

