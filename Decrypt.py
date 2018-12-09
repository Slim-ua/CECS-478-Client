# -*- coding: utf-8 -*-
"""
Created on Thu Oct 18 14:51:06 2018

@author: Kyle Westmoreland
"""

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding as Pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def runDecryption(ct, iv, HMAC_signature_in, derived_key_AES, derived_key_HMAC):
    #Regenerate HMAC tag with decrypted HMAC key
    HMAC_tag = hmac.HMAC(derived_key_HMAC, hashes.SHA256(), backend=default_backend())
    HMAC_tag.update(ct)

    #Verify ciphertext has not been corrupted
    HMAC_tag.verify(HMAC_signature_in)
    
    #Load AES Key
    decCipher = Cipher(algorithms.AES(derived_key_AES), modes.CBC(iv), backend=default_backend())
    
    #Decrypt
    decryptor = decCipher.decryptor()
    padded_plaintext = decryptor.update(ct) + decryptor.finalize()
    
    # PKCS#7 Un-padding used for decrypted message
    unpadder = Pad.PKCS7(128).unpadder()
    unpadded_plaintext = unpadder.update(padded_plaintext)
    unpadded_plaintext += unpadder.finalize()

    return unpadded_plaintext
            