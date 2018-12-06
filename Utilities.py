# -*- coding: utf-8 -*-
"""
Created on Wed Dec  5 17:59:29 2018

@author: Luisa
"""
import sys, requests

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
    else: #Register
        username = input(createNameMessage)
        password = input(createPassMessage)
        
    PARAMS = {'name':username, 'password':password}
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
    
    if choice == "3": #Post a message
        message = input(enterAMessage)
        receiver = input(enterAReceiver)
        PARAMS = {'sender':username, 'receiver':receiver, 
                  'message':message}
    
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
            printMessage(msg)            
            if msg['status'] != readStatusMessage:
                changeMessageStatusToRead(msg, sessionToken)

                
def viewAllUnreadMessagesManager(data, sessionToken):
    readedMessages = 0 
    if not data:
        print(noMessagesAvailable)
    else:
        for msg in data:
            if msg['status'] == 'Unread' or msg['status'] == 'New':
                printMessage(msg)
                changeMessageStatusToRead(msg, sessionToken)
                readedMessages += 1
                 
        if readedMessages == 0:
            print(noUnreadMessagesAvailable)