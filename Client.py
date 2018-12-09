# -*- coding: utf-8 -*-
"""
Created on Sun Dec  2 18:24:23 2018
@author: Kyle Westmoreland and Luis Bri Pérez
"""

#Ideas: 
# Add a delete-all message function. 

######
###### From research, in order to keep private key locally on device,
###### it needs to stay logged in: if a different account logs in, maybe 
###### have the keys be deleted -> need to make new keypair and wouldn't be able
###### to decrypt old messages anymore 

###### Currently set up to work using same 1 pair regardless of who logs in

import requests, threading, time, ECDH, Encrypt, Decrypt, binascii
from Utilities import logedInMenu, welcomeMenu, logOrRegister, handleApiResponse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

#Global Variables
check_For_Messages = False
welcomeMenuText = "1 = Sign-In || 2 = Register || 3 = Exit:\n"
logedInMenuText = ("1 = View All Messages || 2 = View All Unread Messages"
                   "|| 3 = Post Message || 4 = View Sent Messages" 
                   "|| 5 = Delete A Message || 6 = Sign-Out:\n")
welcomeMessage = "Welcome to BrivateKeyle Chat"
baseURL = "https://www.brivatekeyle.me/api/"
notSignedInMessage = "\nCurrently Not Signed In."
signedInMessage = "\nCurrently Signed In."

#method for pooling in the background for new messages
def Pooling():
    while check_For_Messages == True:
        URL = "https://www.brivatekeyle.me/messages" + "/" + username
        API_Type = "get"
        HEADERS = {'x-access-token':sessionToken}
        PARAMS = {}
        response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
        data = response.json()
        for msg in data:
            if msg["status"] == 'New':
                print('New message received from:')
                if 'sender' in msg:
                    print(msg['sender'])
                print()
                URL = "https://www.brivatekeyle.me/message/" + msg['_id']
                API_Type = "put"
                HEADERS = {'x-access-token':sessionToken}
                PARAMS = {'status':'Unread'}
                MakeRequest(URL, PARAMS, HEADERS, API_Type)
        time.sleep(2)

def Session(sessionToken, username):
    p = threading.Thread(name = 'Pooling', target = Pooling)
    p.start()
    while 1:
        while 1:
            global check_For_Messages
            choice = input(logedInMenuText)
            # Get URL and type of HTTP request based on menu choice
            URL, API_Type, check_For_Messages, exitCode = logedInMenu(choice, username)
            if exitCode == "1":
                break
            elif exitCode == "2":
                return
                
    
        print()
        if choice == "1":
            #Generate/retrieve set of ECDH key pairs
            DH_private_key = ECDH.GenerateKeyPairs()
            
            HEADERS = {'x-access-token':sessionToken}
            PARAMS = {}
        elif choice == "2":
            #Generate/retrieve set of ECDH key pairs
            DH_private_key = ECDH.GenerateKeyPairs()
            
            HEADERS = {'x-access-token':sessionToken}
            PARAMS = {}
        elif choice == "3":
            #Generate/retrieve set of ECDH key pairs
            DH_private_key = ECDH.GenerateKeyPairs()
            receiver = input("Enter the receiver:\n")
            #retrieve/verify receiver's key
            URL = "https://www.brivatekeyle.me/api/users/" + receiver
            API_Type = "get"
            HEADERS = {'x-access-token':sessionToken}
            PARAMS = {}
            response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
            data = response.json()
            #print(data)
            for msg in data:
                if 'DH_Pub_Key' in msg:
                    Receiver_DH_Pub_Key = serialization.load_pem_public_key(msg['DH_Pub_Key'].encode(), default_backend())
                else:
                    print("Error, no DH_Pub_Key found.")
                if 'Signed_DH_Pub_Key' in msg:
                    Receiver_Signed_DH_Pub_Key = binascii.unhexlify(msg['Signed_DH_Pub_Key'])
                else:
                    print("Error, no Signed_DH_Pub_Key found.")
                if 'RSA_Pub_Key' in msg:
                    Receiver_RSA_Pub_Key = serialization.load_pem_public_key(msg['RSA_Pub_Key'].encode(), default_backend())
                else:
                    print("Error, no RSA_Pub_Key found.")
            
            #In sender, retrieve receiver's RSA Public Key + Signed DH Public Key + DH Public Key and Verify
            Receiver_RSA_Pub_Key.verify(
                    Receiver_Signed_DH_Pub_Key,
                    Receiver_DH_Pub_Key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256())
            
            shared_key = DH_private_key.exchange(ec.ECDH(), Receiver_DH_Pub_Key)
            derived_key_AES = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=b'100',  
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)
            
            derived_key_HMAC = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=b'99',  
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)
            message = input("Enter your message:\n")
            ct, iv, HMAC_signature = Encrypt.runEncryption(message,
                                  derived_key_AES, derived_key_HMAC)
            
            URL = "https://www.brivatekeyle.me/messages"
            API_Type = "post"
            HEADERS = {'x-access-token':sessionToken}
            PARAMS = {'sender':username, 'receiver':receiver, 
                      'message':binascii.hexlify(ct), 'iv':binascii.hexlify(iv), 'signature':binascii.hexlify(HMAC_signature)}
        elif choice == "4":
            HEADERS = {'x-access-token':sessionToken}
            PARAMS = {}
        elif choice == "5":
            HEADERS = {'x-access-token':sessionToken}
            PARAMS = {}
        
        response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
        data = response.json()
        
        if choice == "1":
            unread_Flag = False
            if not data:
                print('No Messages Available.')
            else:
                for msg in data:
                    if 'Message_date' in msg:
                        print('Date: ' + msg['Message_date'])
                    if 'sender' in msg:
                        print('Sent From: ' + msg['sender'])
                    if 'iv' in msg:
                        #print('iv: ' + msg['iv'])
                        iv = msg['iv']
                    
                    if 'signature' in msg:
                        #print('HMAC_signature: ' + msg['signature'])
                        HMAC_signature = msg['signature']
                    if 'message' in msg:
                        #print('Encrypted Message: ' + msg['message'])
                        ct = msg['message']
                        
                        #retrieve/verify sender's key
                        URL = "https://www.brivatekeyle.me/api/users/" + msg['sender']
                        API_Type = "get"
                        HEADERS = {'x-access-token':sessionToken}
                        PARAMS = {}
                        response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
                        data2 = response.json()
                        #print("\nFFF")
                        #print(data2)
                        for msg2 in data2:
                            if 'DH_Pub_Key' in msg2:
                                #print(msg2['DH_Pub_Key'].encode())
                                Sender_DH_Pub_Key = serialization.load_pem_public_key(msg2['DH_Pub_Key'].encode(), default_backend())
                            else:
                                print("Error, no DH_Pub_Key found.")
                            if 'Signed_DH_Pub_Key' in msg2:
                                Sender_Signed_DH_Pub_Key = binascii.unhexlify(msg2['Signed_DH_Pub_Key'])
                            else:
                                print("Error, no DH_Pub_Key found.")
                            if 'RSA_Pub_Key' in msg2:
                                Sender_RSA_Pub_Key = serialization.load_pem_public_key(msg2['RSA_Pub_Key'].encode(), default_backend())
                            else:
                                print("Error, no RSA_Pub_Key found.")
                            
                            Sender_RSA_Pub_Key.verify(
                                Sender_Signed_DH_Pub_Key,
                                Sender_DH_Pub_Key.public_bytes(
                                        encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                                ),
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA256())
                                
                            shared_key = DH_private_key.exchange(ec.ECDH(), Sender_DH_Pub_Key)
                            derived_key_AES = HKDF(
                                algorithm=hashes.SHA512(),
                                length=32,
                                salt=b'100',  
                                info=b'handshake data',
                                backend=default_backend()
                            ).derive(shared_key)
                            
                            derived_key_HMAC = HKDF(
                                algorithm=hashes.SHA512(),
                                length=32,
                                salt=b'99',  
                                info=b'handshake data',
                                backend=default_backend()
                            ).derive(shared_key)
                        
                        decrypted_msg = Decrypt.runDecryption(binascii.unhexlify(ct), binascii.unhexlify(iv), binascii.unhexlify(HMAC_signature), derived_key_AES, derived_key_HMAC)
                    
                    print('\nDecrypted Message: ' + decrypted_msg.decode())
                    print()
                    
                    if msg['status'] != 'Read':
                        #Changes message 'status' to Read
                        URL = "https://www.brivatekeyle.me/message/" + msg['_id']
                        API_Type = "put"
                        HEADERS = {'x-access-token':sessionToken}
                        PARAMS = {'status':'Read'}
                        MakeRequest(URL, PARAMS, HEADERS, API_Type)
                        
                        unread_Flag = True
                
        elif choice == "2":
            unread_Flag = False
            if not data:
                print('No Unread Messages Available.')
            else:
                for msg in data:
                    if msg['status'] == 'Unread' or msg['status'] == 'New':
                        if 'Message_date' in msg:
                            print('Date: ' + msg['Message_date'])
                        if 'sender' in msg:
                            print('Sent From: ' + msg['sender'])
                        if 'message' in msg:
                            #print('Encrypted Message: ' + msg['message'])
                            ct = msg['message']
                            
                            #retrieve/verify sender's key
                            URL = "https://www.brivatekeyle.me/api/users/" + msg['sender']
                            API_Type = "get"
                            HEADERS = {'x-access-token':sessionToken}
                            PARAMS = {}
                            response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
                            data2 = response.json()
                            for msg2 in data2:
                                if 'DH_Pub_Key' in msg2:
                                    #print(msg2['DH_Pub_Key'].encode())
                                    Sender_DH_Pub_Key = serialization.load_pem_public_key(msg2['DH_Pub_Key'].encode(), default_backend())
                                else:
                                    print("Error, no DH_Pub_Key found.")
                                if 'Signed_DH_Pub_Key' in msg2:
                                    Sender_Signed_DH_Pub_Key = binascii.unhexlify(msg2['Signed_DH_Pub_Key'])
                                else:
                                    print("Error, no DH_Pub_Key found.")
                                if 'RSA_Pub_Key' in msg2:
                                    Sender_RSA_Pub_Key = serialization.load_pem_public_key(msg2['RSA_Pub_Key'].encode(), default_backend())
                                else:
                                    print("Error, no RSA_Pub_Key found.")
                                
                                Sender_RSA_Pub_Key.verify(
                                    Sender_Signed_DH_Pub_Key,
                                    Sender_DH_Pub_Key.public_bytes(
                                            encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                                    ),
                                    padding.PSS(
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH
                                    ),
                                    hashes.SHA256())
                                    
                                shared_key = DH_private_key.exchange(ec.ECDH(), Sender_DH_Pub_Key)
                                derived_key_AES = HKDF(
                                    algorithm=hashes.SHA512(),
                                    length=32,
                                    salt=b'100',  
                                    info=b'handshake data',
                                    backend=default_backend()
                                ).derive(shared_key)
                                
                                derived_key_HMAC = HKDF(
                                    algorithm=hashes.SHA512(),
                                    length=32,
                                    salt=b'99',  
                                    info=b'handshake data',
                                    backend=default_backend()
                                ).derive(shared_key)
                            
                            if 'iv' in msg:
                                #print('iv: ' + msg['iv'])
                                iv = msg['iv']
                            
                            if 'signature' in msg:
                                #print('HMAC_signature: ' + msg['signature'])
                                HMAC_signature = msg['signature']
                            
                            decrypted_msg = Decrypt.runDecryption(binascii.unhexlify(ct), binascii.unhexlify(iv), binascii.unhexlify(HMAC_signature), derived_key_AES, derived_key_HMAC)
                            
                            print('\nDecrypted Message: ' + decrypted_msg.decode())
                        print()
                        
                        #Changes message 'status' to Read
                        URL = "https://www.brivatekeyle.me/message/" + msg['_id']
                        API_Type = "put"
                        HEADERS = {'x-access-token':sessionToken}
                        PARAMS = {'status':'Read'}
                        MakeRequest(URL, PARAMS, HEADERS, API_Type)
                        
                        unread_Flag = True
                    else:
                        #Prints message if no messages were found from end of search
                        if msg['_id'] == data[-1]['_id']:
                            if unread_Flag == False:
                                print('No Unread Messages Available.')
                                
        elif choice == "3":
            if '_id' in data:
                print('Message Posted Successfully.')
        elif choice == "4":
            sent_Flag = False
            if not data:
                print('No Messages Sent.')
            else:
                for msg in data:
                    if msg['sender'] == username:
                        if 'Message_date' in msg:
                            print('Date: ' + msg['Message_date'])
                        if 'receiver' in msg:
                            print('Sent To: ' + msg['receiver'])
                        #print('Encrypted Message: ' + msg['message'])
                        ct = msg['message']
                        receiver = msg['receiver']
                        #retrieve/verify sender's key
                        URL = "https://www.brivatekeyle.me/api/users/" + msg['sender']
                        API_Type = "get"
                        HEADERS = {'x-access-token':sessionToken}
                        PARAMS = {}
                        response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
                        data2 = response.json()
                        for msg2 in data2:
                            if 'DH_Pub_Key' in msg2:
                                #print(msg2['DH_Pub_Key'].encode())
                                Sender_DH_Pub_Key = serialization.load_pem_public_key(msg2['DH_Pub_Key'].encode(), default_backend())
                            else:
                                print("Error, no DH_Pub_Key found.")
                            if 'Signed_DH_Pub_Key' in msg2:
                                Sender_Signed_DH_Pub_Key = binascii.unhexlify(msg2['Signed_DH_Pub_Key'])
                            else:
                                print("Error, no DH_Pub_Key found.")
                            if 'RSA_Pub_Key' in msg2:
                                Sender_RSA_Pub_Key = serialization.load_pem_public_key(msg2['RSA_Pub_Key'].encode(), default_backend())
                            else:
                                print("Error, no RSA_Pub_Key found.")
                            
                            Sender_RSA_Pub_Key.verify(
                                Sender_Signed_DH_Pub_Key,
                                Sender_DH_Pub_Key.public_bytes(
                                        encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                                ),
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA256())
                            
                            
                            URL = "https://www.brivatekeyle.me/api/users/" + receiver
                            API_Type = "get"
                            HEADERS = {'x-access-token':sessionToken}
                            PARAMS = {}
                            response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
                            data3 = response.json()
                            #print(data)
                            for msg3 in data3:
                                if 'DH_Pub_Key' in msg3:
                                    Receiver_DH_Pub_Key = serialization.load_pem_public_key(msg3['DH_Pub_Key'].encode(), default_backend())
                                else:
                                    print("Error, no DH_Pub_Key found.")
                            
                            
                            shared_key = DH_private_key.exchange(ec.ECDH(), Receiver_DH_Pub_Key)
                            derived_key_AES = HKDF(
                                algorithm=hashes.SHA512(),
                                length=32,
                                salt=b'100',  
                                info=b'handshake data',
                                backend=default_backend()
                            ).derive(shared_key)
                            
                            derived_key_HMAC = HKDF(
                                algorithm=hashes.SHA512(),
                                length=32,
                                salt=b'99',  
                                info=b'handshake data',
                                backend=default_backend()
                            ).derive(shared_key)
                        
                        if 'iv' in msg:
                            #print('iv: ' + msg['iv'])
                            iv = msg['iv']
                        
                        if 'signature' in msg:
                            #print('HMAC_signature: ' + msg['signature'])
                            HMAC_signature = msg['signature']
                        
                        decrypted_msg = Decrypt.runDecryption(binascii.unhexlify(ct), binascii.unhexlify(iv), binascii.unhexlify(HMAC_signature), derived_key_AES, derived_key_HMAC)
                        
                        print('\nDecrypted Message: ' + decrypted_msg.decode())
                        sent_Flag = True
                    else:
                        if msg['_id'] == data[-1]['_id']:
                            if sent_Flag == False:
                                print('No Messages Sent.')

        elif choice == "5":
            amount = 0
            delete_Flag = False
            if not data:
                print('No Messages Available.')
            else:
                for msg in data:
                    if msg['sender'] == username:
                        amount = amount + 1
                        print("Message #" + str(amount) + ":")
                        if 'Message_date' in msg:
                            print('Date: ' + msg['Message_date'])
                        if 'receiver' in msg:
                                print('Sent To: ' + msg['receiver'])
                        if 'message' in msg:
                            #print('Encrypted Message: ' + msg['message'])
                            ct = msg['message']
                            receiver = msg['receiver']
                            
                            #retrieve/verify sender's key
                            URL = "https://www.brivatekeyle.me/api/users/" + msg['sender']
                            API_Type = "get"
                            HEADERS = {'x-access-token':sessionToken}
                            PARAMS = {}
                            response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
                            data2 = response.json()
                            for msg2 in data2:
                                if 'DH_Pub_Key' in msg2:
                                    #print(msg2['DH_Pub_Key'].encode())
                                    Sender_DH_Pub_Key = serialization.load_pem_public_key(msg2['DH_Pub_Key'].encode(), default_backend())
                                else:
                                    print("Error, no DH_Pub_Key found.")
                                if 'Signed_DH_Pub_Key' in msg2:
                                    Sender_Signed_DH_Pub_Key = binascii.unhexlify(msg2['Signed_DH_Pub_Key'])
                                else:
                                    print("Error, no DH_Pub_Key found.")
                                if 'RSA_Pub_Key' in msg2:
                                    Sender_RSA_Pub_Key = serialization.load_pem_public_key(msg2['RSA_Pub_Key'].encode(), default_backend())
                                else:
                                    print("Error, no RSA_Pub_Key found.")
                                
                                Sender_RSA_Pub_Key.verify(
                                    Sender_Signed_DH_Pub_Key,
                                    Sender_DH_Pub_Key.public_bytes(
                                            encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                                    ),
                                    padding.PSS(
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH
                                    ),
                                    hashes.SHA256())
                                
                                URL = "https://www.brivatekeyle.me/api/users/" + receiver
                                API_Type = "get"
                                HEADERS = {'x-access-token':sessionToken}
                                PARAMS = {}
                                response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
                                data3 = response.json()
                                #print(data)
                                for msg3 in data3:
                                    if 'DH_Pub_Key' in msg3:
                                        Receiver_DH_Pub_Key = serialization.load_pem_public_key(msg3['DH_Pub_Key'].encode(), default_backend())
                                    else:
                                        print("Error, no DH_Pub_Key found.")
                                
                                
                                shared_key = DH_private_key.exchange(ec.ECDH(), Receiver_DH_Pub_Key)
                                derived_key_AES = HKDF(
                                    algorithm=hashes.SHA512(),
                                    length=32,
                                    salt=b'100',  
                                    info=b'handshake data',
                                    backend=default_backend()
                                ).derive(shared_key)
                                
                                derived_key_HMAC = HKDF(
                                    algorithm=hashes.SHA512(),
                                    length=32,
                                    salt=b'99',  
                                    info=b'handshake data',
                                    backend=default_backend()
                                ).derive(shared_key)
                            
                            if 'iv' in msg:
                                #print('iv: ' + msg['iv'])
                                iv = msg['iv']
                            
                            if 'signature' in msg:
                                #print('HMAC_signature: ' + msg['signature'])
                                HMAC_signature = msg['signature']
                            
                            decrypted_msg = Decrypt.runDecryption(binascii.unhexlify(ct), binascii.unhexlify(iv), binascii.unhexlify(HMAC_signature), derived_key_AES, derived_key_HMAC)
                            
                            print('\nDecrypted Message: ' + decrypted_msg.decode())
                        print()
                        delete_Flag = True
                    else:
                        amount = amount + 1
                        if msg['_id'] == data[-1]['_id']:
                            if delete_Flag == False:
                                print('No Messages Available.')
                while 1:
                    if delete_Flag == False:
                        break
                    try:
                        delete_Numb = int(input('Please enter which message # you would like to delete (0 = Cancel):\n'))
                        delete_Numb = delete_Numb - 1
                    except ValueError:
                        print('Input is not a number.')
                    #Deletes a message based on delete_Numb
                    if delete_Numb == -1:
                        print('Canceling Deletion.')
                        break
                    else:
                        if delete_Numb < 0 or delete_Numb > len(data) - 1:
                            print('Invalid Message Selection.')
                        else:
                            if data[delete_Numb]['sender'] == username:
                                URL = "https://www.brivatekeyle.me/message/" + data[delete_Numb]['_id']
                                API_Type = "delete"
                                HEADERS = {'x-access-token':sessionToken}
                                PARAMS = {}
                                MakeRequest(URL, PARAMS, HEADERS, API_Type)
                                print('Message Deleted Successfully.')
                                break
                            else:
                                print('Invalid Message Selection.')
            
        else:
            print("Invalid Choice.")
        print()

def MakeRequest(URL, PARAMS, HEADERS, API_Type):
    # sending get request and saving the response as response object 
    
    if API_Type == "get":
        r = requests.get(url = URL, params = PARAMS, headers = HEADERS)
    elif API_Type == "post":
        r = requests.post(url = URL, data = PARAMS, headers = HEADERS)
    elif API_Type == "put":
        r = requests.put(url = URL, data = PARAMS, headers = HEADERS)
    elif API_Type == "delete":
        r = requests.delete(url = URL, data = PARAMS, headers = HEADERS)
    else:
        r = "FAIL"
        print("Invalid API_Type.")
    return r
    

if __name__ == '__main__':   
    while 1:
        print(welcomeMessage)
        while 1:
            choice = input(welcomeMenuText)
            URL, API_Type, out = welcomeMenu(choice)
            if out == True:
                break
         
        print()        
        # Defining parameters for API Request based on choice
        PARAMS, HEADERS = logOrRegister(choice) 
        # Make a request to the API
        response = MakeRequest(URL, PARAMS, HEADERS, API_Type)       
        # Get data from the API response
        sessionToken, username = handleApiResponse(response.json())
        # Determine status of the session
        if sessionToken is None:
            print(notSignedInMessage)
        else:
            print(signedInMessage)
            check_For_Messages = True
            Session(sessionToken, username)
            
        print()
          