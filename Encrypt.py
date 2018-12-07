# -*- coding: utf-8 -*-
"""
Created on Tue Oct 16 16:07:03 2018

@author: Kyle Jr
"""

import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding as Pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization




def loadPrivateKey(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    privateKey = load_pem_private_key(pemlines, b"brivatekeyle", default_backend())
    return privateKey
    
def DH_Signature(DH_pubKey):
    #Load private key
    #RSA_Private_Key = loadPrivateKey(b"C:\Users\Luisa\Documents\RSA_private.pem")
    RSA_Private_Key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
            )
    RSA_Public_Key = RSA_Private_Key.public_key()
    signed_DH_pubKey = RSA_Private_Key.sign(
        DH_pubKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
                #encryption_algorithm=serialization.BestAvailableEncryption(b'testpassword')
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signed_DH_pubKey, RSA_Public_Key


def loadPublicKey(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    publicKey = load_pem_public_key(pemlines, default_backend())
    return publicKey

def encrypt(cipher, plaintext):
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def runEncryption(msg, derived_key_1_AES, derived_key_1_HMAC):
    #Setup encryption variables
    
    #public_key_hold = loadPublicKey(b"C:\Users\Luisa\Documents\RSA_public.pem")
    
    
    
    
    
    backend = default_backend()
    keyAES = derived_key_1_AES
    iv = os.urandom(16)
    
    # PKCS#7 Padding used for encrypting message
    padder = Pad.PKCS7(algorithms.AES.block_size).padder()
    padded_msg = padder.update(msg.encode()) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(keyAES), modes.CBC(iv), backend=backend)
    
    #Encrypt text
    ct = encrypt(cipher, padded_msg)
    
    
    
    keyHMAC = derived_key_1_HMAC
    h = hmac.HMAC(keyHMAC, hashes.SHA256(), backend=default_backend())
    h.update(ct)
    HMAC_signature = h.finalize()
    
    #Sign ciphertext
    #signature = sign(ct)
    
    #Setup verification signature (only for text purposes)
    #h2 = hmac.HMAC(key2, hashes.SHA256(), backend=default_backend())
    #h2.update(ct)
    
    #Verify signature (no message == OK)
    #h2.verify(signature)
    
    
    
    #Setup signature
    #h = hmac.HMAC(os.urandom(32), hashes.SHA256(), backend=default_backend())
    
    #Sign ciphertext
    #print(ct)
    #print(h)
    #h.update(b"Test")
    #h.finalize()
    #print(h)
    #print("Test Verify")
    #print(h.verify(b"Test"))
    #signature = h.finalize()
    #print(signature)
    
    print ("DH Encryption Successful.")
    return ct, iv, HMAC_signature
