# -*- coding: utf-8 -*-
"""
Created on Wed Dec  5 17:59:29 2018

@author: Luisa
"""
import sys

baseURL = "https://www.brivatekeyle.me/"
typeNameMessage = "Please type in username:\n"
typePassMessage = "Please type in password:\n"
createNameMessage = "Please create a username:\n"
createPassMessage = "Please create a password:\n"
enterAMessage = "Enter your message:\n"
enterAReceiver = "Enter the receiver:\n"
invalidChoiceMessage = "Invalid Choice."
signingOutMessage = "\nSigning Out."

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

       