# -*- coding: utf-8 -*-
"""
Created on Thu Oct 18 14:51:06 2018

@author: Kyle Jr
"""

import json
import base64
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding as Pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key



def rsaDecrypt(ciphertext, privateKey):
    plaintext = privateKey.decrypt(
            ciphertext,
            padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
            )
    )
    return plaintext

def loadPrivateKey(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    privateKey = load_pem_private_key(pemlines, b"brivatekeyle", default_backend())
    return privateKey



def runDecryption(ct, iv, HMAC_signature_in, derived_key_AES, derived_key_HMAC):
    #Extract JSON file data
    #with open(JSON_Data_Path) as infile:
     #   data = json.load(infile)
    
    #rsaCiphertext = base64.b64decode(data[JSON_D_1])
    aesCiphertext = ct
    #hmacSignature = base64.b64decode(data[JSON_D_3])
    #privateKeyPath = base64.b64decode(data[JSON_D_4])
    #iv = base64.b64decode(data[JSON_D_5])
    
    #Load private key
    #privateKey = loadPrivateKey(privateKeyPath)
    #privateKey1 = private_key
    
    #Decrypt RSA ciphertext
    #aesAndHmac = rsaDecrypt(rsaCiphertext, privateKey)
    #aesAndHmac = rsaCiphertext
    
    #Get AES key and HMAC key from RSA plaintext
    aesKey = derived_key_AES
    hmacKey = derived_key_HMAC
    #print(aesKey)
    #Regenerate HMAC tag with decrypted HMAC key
    HMAC_tag = hmac.HMAC(hmacKey, hashes.SHA256(), backend=default_backend())
    HMAC_tag.update(aesCiphertext)
    #HMAC_signature_new = hmacTag.finalize()
    #HMAC_tag.update(aesCiphertext)
    #Verify ciphertext has not been corrupted
    HMAC_tag.verify(HMAC_signature_in)
    
    #Load AES Key
    decCipher = Cipher(algorithms.AES(aesKey), modes.CBC(iv), backend=default_backend())
    
    #Decrypt
    decryptor = decCipher.decryptor()
    padded_plaintext = decryptor.update(aesCiphertext) + decryptor.finalize()
    # PKCS#7 Un-padding used for decrypted message
    unpadder = Pad.PKCS7(128).unpadder()
    
    #print("Padded Plaintext:")
    #print(padded_plaintext)
    unpadded_plaintext = unpadder.update(padded_plaintext)
    unpadded_plaintext += unpadder.finalize()

    #print(unpadded_plaintext)
    return unpadded_plaintext
            