from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
from pycose.keys import CoseKey
from pycose.keys.keytype import KtyRSA
from pycose.keys.keyparam import (RSAKpN, RSAKpE, RSAKpD, RSAKpP, RSAKpDP, RSAKpDQ, RSAKpQInv, RSAKpQ, KpKty)
from pycose.messages import Sign1Message
from pycose.headers import Algorithm
from pycose.algorithms import Ps256
import binascii

def sign(message:bytes, keyfile:str) -> bytes:

    key = RSA.import_key(open(keyfile).read())

    cose_key = CoseKey.from_dict({
        KpKty: KtyRSA,
        RSAKpN: long_to_bytes(key.n),
        RSAKpE: long_to_bytes(key.e),
        RSAKpD: long_to_bytes(key.d),
        RSAKpP: long_to_bytes(key.p),
        RSAKpQ: long_to_bytes(key.q),
        RSAKpDP: long_to_bytes(key.dp),
        RSAKpDQ: long_to_bytes(key.dq),
        RSAKpQInv: long_to_bytes(key.invq),
    })

    msg = Sign1Message(
        phdr= {Algorithm: Ps256},
        payload=message,
        key=cose_key
    )

    encoded=msg.encode()

    return encoded

def Main() -> None:
    message = b'\x00\x01\x02\x03'
    keyname="../certificates/update-linux-sign-private-4096.pem"
    signature=sign(message, keyname)
    print("Signature: ")
    print(binascii.hexlify(signature))
    print("\n")


if __name__ == '__main__':
    Main()

