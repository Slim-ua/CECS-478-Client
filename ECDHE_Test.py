# -*- coding: utf-8 -*-
"""
Created on Wed Dec  5 14:04:07 2018

@author: Kyle Jr
"""

import Encrypt, Decrypt, os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Generate a private key for use in the exchange.
DH_private_key = ec.generate_private_key(
    ec.SECP384R1(), default_backend()
)
# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key
# and get a public key from that.
peer_DH_private_key = ec.generate_private_key(
    ec.SECP384R1(), default_backend()
)


#print("\nPublic Key #2: ")
#print(peer_public_key)


#print("\nShared Key #1: " + str(shared_key1))
#print("\nShared Key #2: " + str(shared_key2))
# Perform key derivation.
#Yourself
#derived_key1 = HKDF(
#    algorithm=hashes.SHA512(),
#    length=32,
#    salt=None,  #CAN DETERMINE SALT VALUE, NEEDS TO MATCH
#    info=b'handshake data',
#    backend=default_backend()
#).derive(shared_key1)

#Target of message
#derived_key2 = HKDF(
#    algorithm=hashes.SHA512(),
#    length=32,
#    salt=None,  #CAN DETERMINE SALT VALUE, NEEDS TO MATCH
#    info=b'handshake data',
#    backend=default_backend()
#).derive(shared_key1)


# Ethemeral: For the next handshake we MUST generate another private key.
private_key2 = ec.generate_private_key(
    ec.SECP384R1(), default_backend()
)
peer_private_key2 = ec.generate_private_key(
    ec.SECP384R1(), default_backend()
)

shared_key3 = private_key2.exchange(ec.ECDH(), peer_private_key2.public_key())
shared_key4 = peer_private_key2.exchange(ec.ECDH(), private_key2.public_key())

derived_key3 = HKDF(
    algorithm=hashes.SHA512(),
    length=32,
    salt=b'100',  #CAN DETERMINE SALT VALUE, NEEDS TO MATCH
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key3)
derived_key4 = HKDF(
    algorithm=hashes.SHA512(),
    length=32,
    salt=b'100',  #CAN DETERMINE SALT VALUE, NEEDS TO MATCH
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key4)

signed_DH_pubKey, RSA_pubKey = Encrypt.DH_Signature(DH_private_key.public_key())
signed_peer_DH_pubKey, peer_RSA_pubKey = Encrypt.DH_Signature(peer_DH_private_key.public_key())

peer_RSA_pubKey.verify(
        signed_peer_DH_pubKey,
        peer_DH_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())

RSA_pubKey.verify(
        signed_DH_pubKey,
        DH_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())

#Client 1
shared_key1 = DH_private_key.exchange(ec.ECDH(), peer_DH_private_key.public_key())
derived_key_1_AES = HKDF(
    algorithm=hashes.SHA512(),
    length=32,
    salt=b'100',  
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key1)

#Target of message
derived_key_1_HMAC = HKDF(
    algorithm=hashes.SHA512(),
    length=32,
    salt=b'99',  
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key1)

#Client 2
shared_key2 = peer_DH_private_key.exchange(ec.ECDH(), DH_private_key.public_key())
derived_key_2_AES = HKDF(
    algorithm=hashes.SHA512(),
    length=32,
    salt=b'100',  
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key2)

#Target of message
derived_key_2_HMAC = HKDF(
    algorithm=hashes.SHA512(),
    length=32,
    salt=b'99',  
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key2)

message = "Hello World! Hello Kyle! Hello Luis!"
ct, iv, HMAC_signature = Encrypt.runEncryption(message,
                      derived_key_1_AES, derived_key_1_HMAC)

#print("CipherText:")
#print(ct)

#print("derived_key_1_AES:")
#print(derived_key_1_AES)

#print("derived_key_2_AES:")
#print(derived_key_1_HMAC)

print("Decrypted Message:")
print(Decrypt.runDecryption(ct, iv, HMAC_signature, derived_key_2_AES, derived_key_2_HMAC))
#Call decryption module
#Decrypt.runDecryption(b"C:\Users\Kyle Jr\OneDrive\Kyle Jr.'s Files\Documents\CECS 478\data.json",
                     # "RSA ciphertext",
                     # "AES ciphertext",
                     # "HMAC signature",
                     # "RSA Private Key Path",
                     # "IV",
                     # private_key)
