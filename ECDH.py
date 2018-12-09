# -*- coding: utf-8 -*-
"""
Created on Wed Dec  5 21:23:51 2018

@author: Kyle Westmoreland
"""

import os, sys, Encrypt

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


def GenerateKeyPairs():
    DHprivateKeyPath = os.path.dirname(os.path.realpath(sys.argv[0])) + "\DH_private.pem"
    if os.path.exists(DHprivateKeyPath):
        DH_private_key = Encrypt.loadPrivateKey(DHprivateKeyPath)
    else:
        #Generate a private key for use in the exchange.
        DH_private_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend()
        )
        #Stores the DH Private Key
        Encrypt.savePrivateKey(DH_private_key, DHprivateKeyPath)
        
    return DH_private_key
    