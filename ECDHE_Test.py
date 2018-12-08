# -*- coding: utf-8 -*-
"""
Created on Wed Dec  5 14:04:07 2018

@author: Kyle Jr
"""

import Encrypt, Decrypt, os, sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

#-----First, both sides need to generate/retrieve a Diffie Hellman Private Key

DHprivateKeyPath = os.path.dirname(os.path.realpath(sys.argv[0])) + "\DH_private.pem"
if os.path.exists(DHprivateKeyPath):
    print("DH Private Key Exists.\n")
    DH_private_key = Encrypt.loadPrivateKey(DHprivateKeyPath)
else:
    print("Generating new DH Private Key.\n")
    #Generate a private key for use in the exchange.
    DH_private_key = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    #Stores the DH Private Key
    Encrypt.savePrivateKey(DH_private_key, DHprivateKeyPath)

PeerDHprivateKeyPath = os.path.dirname(os.path.realpath(sys.argv[0])) + "\Peer_DH_private.pem"
if os.path.exists(PeerDHprivateKeyPath):
    print("Peer DH Private Key Exists.\n")
    peer_DH_private_key = Encrypt.loadPrivateKey(PeerDHprivateKeyPath)
else:
    print("Generating new Peer DH Private Key.\n")
    #Generate a private key for use in the exchange.
    # In a real handshake the peer_public_key will be received from the
    # other party. For this example we'll generate another private key
    # and get a public key from that.
    peer_DH_private_key = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    #Stores the DH Private Key
    Encrypt.savePrivateKey(peer_DH_private_key, PeerDHprivateKeyPath)

#-----Then both sides sign their DH Public Key with a generated/retrieved RSA Private Key
    
signed_DH_pubKey, RSA_pubKey = Encrypt.DH_Signature(DH_private_key.public_key())
signed_peer_DH_pubKey, peer_RSA_pubKey = Encrypt.DH_Signature_Peer(peer_DH_private_key.public_key())

#-----Then both sides verify each other's signed DH Public Keys
#-----with their normal DH Public Key
#ADD TRY CASE FOR IF VERIFY FAILS

#In client 1, retrieve client 2 RSA Public Key + Signed DH Public Key + DH Public Key and Verify
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
        
#In client 2, retrieve client 1 RSA Public Key + Signed DH Public Key + DH Public Key and Verify
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

#-----If valid, both sides generate a shared secret key that is identical.
#-----Both sides derive two keys from the secret key, one for AES, the other for HMAC

#Client 1
shared_key1 = DH_private_key.exchange(ec.ECDH(), peer_DH_private_key.public_key())

derived_key_1_AES = HKDF(
    algorithm=hashes.SHA512(),
    length=32,
    salt=b'100',  
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key1)

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

derived_key_2_HMAC = HKDF(
    algorithm=hashes.SHA512(),
    length=32,
    salt=b'99',  
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key2)

#-----Then the sender creates a message, encrypts it using the two derived keys,
#-----and sends the cipher, iv, and HMAC signature over to the receiver to decrypt

message = "Hello World! Hello Kyle! Hello Luis! A successful ECDH approach!"
ct, iv, HMAC_signature = Encrypt.runEncryption(message,
                      derived_key_1_AES, derived_key_1_HMAC)

print("Decrypted Message:")
#Call decryption module
decrypted_message = Decrypt.runDecryption(ct, iv, HMAC_signature, derived_key_2_AES, derived_key_2_HMAC)
print(decrypted_message)
