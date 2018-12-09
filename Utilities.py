# -*- coding: utf-8 -*-
"""
Created on Wed Dec  5 17:59:29 2018

@author: Luisa
"""
import sys, ECDH, Encrypt, binascii, requests, Decrypt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

baseURL = "https://www.brivatekeyle.me/"
typeNameMessage = "Please type in username:\n"
typePassMessage = "Please type in password:\n"
createNameMessage = "Please create a username:\n"
createPassMessage = "Please create a password:\n"
enterAMessage = "Enter your message:\n"
enterAReceiver = "Enter the receiver:\n"
invalidChoiceMessage = "Invalid Choice."
signingOutMessage = "\nSigning Out."
readStatusMessage = "Read"
noMessagesAvailable = "No Messages Available."
noUnreadMessagesAvailable = "No Unread Messages Available."
noMessagesSent = "No Messages Sent."
messageNText = "Message #"
deleteMessage = "Please enter which message # you would like to delete (0 = Cancel):\n"
notNumberMessage = "Input is not a number."
cancelDeletionMessage = "Canceling Deletion."
invalidSelectionMessage = "Invalid Message Selection."

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

def welcomeMenu(choice):
    URL = ""
    API_Type = ""
    out = False
    if choice == "1":
        URL = baseURL + "api/signin"
        API_Type = "post"
        out = True
    elif choice == "2":
        URL = baseURL + "api/register"
        API_Type = "post"
        out = True
    elif choice == "3":
        print("\nExiting Program.")
        sys.exit()
    else:
        print("Invalid Choice.")
        
    return URL, API_Type, out

def logedInMenu(choice, username):
    URL = baseURL
    check_For_Messages = True
    API_Type = ""
    exitCode = "1" # 0 = do nothing, 1 = break, 2 = return
    if choice == "1":
        URL += "messages" + "/" + username
        API_Type = "get"
    elif choice == "2":
        URL += "messages" + "/" + username
        API_Type = "get"
    elif choice == "3":
        URL += "messages"
        API_Type = "post"
    elif choice == "4":
        URL += "allmessages"
        API_Type = "get"
    elif choice == "5":
        URL += "allmessages"
        API_Type = "get"
    elif choice == "6":
        print(signingOutMessage)
        check_For_Messages = False
        exitCode = "2"
    else:
        print(invalidChoiceMessage)
        exitCode = "0"
        
    return URL, API_Type, check_For_Messages, exitCode

def logOrRegister(choice):
    if choice == "1": #Log in
        username = input(typeNameMessage)
        password = input(typePassMessage)
        #Try to read private_key from local storage, if no key exists, creates pair + store
        DH_private_key = ECDH.GenerateKeyPairs()
        RSA_private_key = Encrypt.RSA_GenerateKeyPairs()
        
        DH_storeable_public_key = DH_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        RSA_storeable_public_key = RSA_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        #Creates signature for DH Public Key
        signed_DH_pubKey = binascii.hexlify(Encrypt.DH_Signature(DH_private_key.public_key(), RSA_private_key))
        
    else: #Register
        username = input(createNameMessage)
        password = input(createPassMessage)
        
        #Create key pairs and stores private keys locally and public keys on server
        DH_private_key = ECDH.GenerateKeyPairs()
        RSA_private_key = Encrypt.RSA_GenerateKeyPairs()
        
        DH_storeable_public_key = DH_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        RSA_storeable_public_key = RSA_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        #Creates signature for DH Public Key
        signed_DH_pubKey = binascii.hexlify(Encrypt.DH_Signature(DH_private_key.public_key(), RSA_private_key))
        
        
    PARAMS = {'name':username, 'password':password, 'DH_Pub_Key':DH_storeable_public_key, 'Signed_DH_Pub_Key':signed_DH_pubKey, 'RSA_Pub_Key':RSA_storeable_public_key}
    HEADERS = {}
    return PARAMS, HEADERS

def handleApiResponse(data):
    sessionToken = None
    userName = ""
    if 'success' in data and data['success']  == True:
        print(data['message'])
        sessionToken = data['token'] if 'token' in data else None
        userName = data['username']
    else:
        print(data['message'])
        
    return sessionToken, userName

def logedInAction(choice, sessionToken, username):
    HEADERS = {'x-access-token':sessionToken}
    PARAMS = {}
    
    return HEADERS, PARAMS


def changeMessageStatusToRead(msg, sessionToken):
    URL = baseURL + "message/" + msg['_id']
    API_Type = "put"
    HEADERS = {'x-access-token':sessionToken}
    PARAMS = {'status':readStatusMessage}
    MakeRequest(URL, PARAMS, HEADERS, API_Type)
    
    
def printMessage(msg):
    if 'Message_date' in msg:
        print('Date: ' + msg['Message_date'])
    if 'sender' in msg:
        print('Sent From: ' + msg['sender'])
    if 'message' in msg:
        print('Message: ' + msg['message'])
    print()
    

def viewAllMessagesManager(data, sessionToken):
    if not data:
        print(noMessagesAvailable)
    else:
        for msg in data:
            if 'Message_date' in msg:
                print('Date: ' + msg['Message_date'])
            if 'sender' in msg:
                print('Sent From: ' + msg['sender'])
            if 'iv' in msg:
                iv = msg['iv']
            
            if 'signature' in msg:
                HMAC_signature = msg['signature']
            if 'message' in msg:
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
                        
                    DH_private_key = ECDH.GenerateKeyPairs()   
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
            print('-----------------------------')
            print()
            
            if msg['status'] != readStatusMessage:
                #Changes message 'status' to Read
                changeMessageStatusToRead(msg, sessionToken)
                
def viewAllUnreadMessagesManager(data, sessionToken):
    unread_Flag = False
    if not data:
        print(noUnreadMessagesAvailable)
    else:
        for msg in data:
            if msg['status'] == 'Unread' or msg['status'] == 'New':
                if 'Message_date' in msg:
                    print('Date: ' + msg['Message_date'])
                if 'sender' in msg:
                    print('Sent From: ' + msg['sender'])
                if 'message' in msg:
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
                            
                        DH_private_key = ECDH.GenerateKeyPairs()   
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
                        iv = msg['iv']
                    
                    if 'signature' in msg:
                        HMAC_signature = msg['signature']
                    
                    decrypted_msg = Decrypt.runDecryption(binascii.unhexlify(ct), binascii.unhexlify(iv), binascii.unhexlify(HMAC_signature), derived_key_AES, derived_key_HMAC)
                    
                    print('\nDecrypted Message: ' + decrypted_msg.decode())
                    print()
                    print('-----------------------------')
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
                        print(noUnreadMessagesAvailable)
            

def sendMessage(username, sessionToken):
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
    response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
    data = response.json()
    if '_id' in data:
        print('Message Posted Successfully.')

def viewSentMessages(data, sessionToken, username):
    sent_Flag = False
    if not data:
        print(noMessagesSent)
    else:
        for msg in data:
            if msg['sender'] == username:
                if 'Message_date' in msg:
                    print('Date: ' + msg['Message_date'])
                if 'receiver' in msg:
                    print('Sent To: ' + msg['receiver'])
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
                    for msg3 in data3:
                        if 'DH_Pub_Key' in msg3:
                            Receiver_DH_Pub_Key = serialization.load_pem_public_key(msg3['DH_Pub_Key'].encode(), default_backend())
                        else:
                            print("Error, no DH_Pub_Key found.")
                    
                    #Generate/retrieve set of ECDH key pairs
                    DH_private_key = ECDH.GenerateKeyPairs()
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
                    iv = msg['iv']
                
                if 'signature' in msg:
                    HMAC_signature = msg['signature']
                
                decrypted_msg = Decrypt.runDecryption(binascii.unhexlify(ct), binascii.unhexlify(iv), binascii.unhexlify(HMAC_signature), derived_key_AES, derived_key_HMAC)
                
                print('\nDecrypted Message: ' + decrypted_msg.decode())
                print()
                print('-----------------------------')
                print()
                sent_Flag = True
            else:
                if msg['_id'] == data[-1]['_id']:
                    if sent_Flag == False:
                        print('No Messages Sent.')

def makeDeleteRequest(data, msgNumber, sessionToken):
    URL = "https://www.brivatekeyle.me/message/" + data[msgNumber]['_id']
    API_Type = "delete"
    HEADERS = {'x-access-token':sessionToken}
    PARAMS = {}
    return MakeRequest(URL, PARAMS, HEADERS, API_Type)
    
    
def deleteAMessage(data, sessionToken, username):
    amount = 0
    delete_Flag = False
    if not data:
        print(noMessagesAvailable)
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
                        for msg3 in data3:
                            if 'DH_Pub_Key' in msg3:
                                Receiver_DH_Pub_Key = serialization.load_pem_public_key(msg3['DH_Pub_Key'].encode(), default_backend())
                            else:
                                print("Error, no DH_Pub_Key found.")
                                
                        #Generate/retrieve set of ECDH key pairs
                        DH_private_key = ECDH.GenerateKeyPairs()
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
                        iv = msg['iv']
                    
                    if 'signature' in msg:
                        HMAC_signature = msg['signature']
                    
                    decrypted_msg = Decrypt.runDecryption(binascii.unhexlify(ct), binascii.unhexlify(iv), binascii.unhexlify(HMAC_signature), derived_key_AES, derived_key_HMAC)
                    
                    print('\nDecrypted Message: ' + decrypted_msg.decode())
                    print()
                    print('-----------------------------')
                    print()
                delete_Flag = True
            else:
                amount = amount + 1
                if msg['_id'] == data[-1]['_id']:
                    if delete_Flag == False:
                        print(noMessagesAvailable)
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
                print(cancelDeletionMessage)
                break
            else:
                if delete_Numb < 0 or delete_Numb > len(data) - 1:
                    print(invalidSelectionMessage)
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
                        print(invalidSelectionMessage)
