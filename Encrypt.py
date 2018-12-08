# -*- coding: utf-8 -*-
"""
Created on Tue Oct 16 16:07:03 2018

@author: Kyle Jr
"""

import os, sys, os.path
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding as Pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

#Saves a private key in the form of a PEM file in the directory named by filename.
#Encrypts the key using the encryption_algorithm parameter as a password.
def savePrivateKey(pk, filename):
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b'brivatekeyle')
    )
    
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)
#Loads an encrypted private key from a PEM file in the directory named by filename. 
#Decrypts the key using the second parameter in load_pem_private_key as a password.
def loadPrivateKey(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
        
    privateKey = load_pem_private_key(pemlines, b"brivatekeyle", default_backend())
    
    return privateKey
    
def DH_Signature(DH_pubKey):
    #Load RSA Private Key if it exists, else generates a new one and stores it.
    privateKeyPath = os.path.dirname(os.path.realpath(sys.argv[0])) + "\RSA_private.pem" #To get directory of current folder
    if os.path.exists(privateKeyPath):
        print("RSA Private Key Exists.\n")
        RSA_Private_Key = loadPrivateKey(privateKeyPath)
    else:
        print("Generating new RSA Private Key.\n")
        #Generates a new RSA Private Key
        RSA_Private_Key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
                )
        #Stores the RSA Private Key
        savePrivateKey(RSA_Private_Key, privateKeyPath)
        
    RSA_Public_Key = RSA_Private_Key.public_key()
    
    signed_DH_pubKey = RSA_Private_Key.sign(
        DH_pubKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
        
    return signed_DH_pubKey, RSA_Public_Key

#For Peer
def DH_Signature_Peer(DH_pubKey):
    #Load RSA Private Key if it exists, else generates a new one and stores it.
    privateKeyPath = os.path.dirname(os.path.realpath(sys.argv[0])) + "\Peer_RSA_private.pem" #To get directory of current folder
    if os.path.exists(privateKeyPath):
        print("Peer RSA Private Key Exists.\n")
        RSA_Private_Key = loadPrivateKey(privateKeyPath)
    else:
        print("Generating new Peer RSA Private Key.\n")
        #Generates a new RSA Private Key
        RSA_Private_Key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
                )
        #Stores the RSA Private Key
        savePrivateKey(RSA_Private_Key, privateKeyPath)
        
    RSA_Public_Key = RSA_Private_Key.public_key()
    
    signed_DH_pubKey = RSA_Private_Key.sign(
        DH_pubKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
        
    return signed_DH_pubKey, RSA_Public_Key

def encrypt(cipher, plaintext):
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def runEncryption(msg, derived_key_1_AES, derived_key_1_HMAC):
    #Setup encryption variable
    iv = os.urandom(16)
    
    # PKCS#7 Padding used for encrypting message
    padder = Pad.PKCS7(algorithms.AES.block_size).padder()
    padded_msg = padder.update(msg.encode()) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(derived_key_1_AES), modes.CBC(iv), backend=default_backend())
    
    #Encrypt text
    ct = encrypt(cipher, padded_msg)
    
    keyHMAC = derived_key_1_HMAC
    h = hmac.HMAC(keyHMAC, hashes.SHA256(), backend=default_backend())
    h.update(ct)
    HMAC_signature = h.finalize()
    
    print ("ECDH, RSA, and HMAC Successful.\n")
    return ct, iv, HMAC_signature
