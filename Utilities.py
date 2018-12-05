# -*- coding: utf-8 -*-
"""
Created on Wed Dec  5 17:59:29 2018

@author: Luisa
"""
import sys

baseURL = "https://www.brivatekeyle.me/api/"
typeNameMessage = "Please type in username:\n"
typePassMessage = "Please type in password:\n"
createNameMessage = "Please create a username:\n"
createPassMessage = "Please create a password:\n"

def welcomeMenu(choice):
    URL = ""
    API_Type = ""
    out = False
    if choice == "1":
        URL = baseURL + "signin"
        API_Type = "post"
        out = True
    elif choice == "2":
        URL = baseURL + "register"
        API_Type = "post"
        out = True
    elif choice == "3":
        print("\nExiting Program.")
        sys.exit()
    else:
        print("Invalid Choice.")
        
    return URL, API_Type, out

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
    user_ID = ""
    if 'success' in data and data['success']  == True:
        print(data['message'])
        sessionToken = data['token'] if 'token' in data else None
        user_ID = data['user_ID']
    else:
        print(data['message'])
        
    return sessionToken, user_ID
       