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

import threading, time, Utilities

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
        response = Utilities.MakeRequest(URL, PARAMS, HEADERS, API_Type)
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
                Utilities.MakeRequest(URL, PARAMS, HEADERS, API_Type)
        time.sleep(2)

def Session(sessionToken, username):
    p = threading.Thread(name = 'Pooling', target = Pooling)
    p.start()
    while 1:
        while 1:
            global check_For_Messages
            choice = input(logedInMenuText)
            # Get URL and type of HTTP request based on menu choice
            URL, API_Type, check_For_Messages, exitCode = Utilities.logedInMenu(choice, username)
            if exitCode == "1":
                break
            elif exitCode == "2":
                return
        print()
        # Determine HTTP headers and parameters based on previous choice on menu
        HEADERS, PARAMS = Utilities.logedInAction(choice, sessionToken, username)   
        # Make API request
        response = Utilities.MakeRequest(URL, PARAMS, HEADERS, API_Type)
        data = response.json()
        
        if choice == "1":
            Utilities.viewAllMessagesManager(data, sessionToken) 
        elif choice == "2":
            Utilities.viewAllUnreadMessagesManager(data, sessionToken)
        elif choice == "3":
            Utilities.sendMessage(username, sessionToken)
        elif choice == "4":
            Utilities.viewSentMessages(data, sessionToken, username)
        elif choice == "5":
            Utilities.deleteAMessage(data, sessionToken, username)

if __name__ == '__main__':   
    while 1:
        print(welcomeMessage)
        while 1:
            choice = input(welcomeMenuText)
            URL, API_Type, out = Utilities.welcomeMenu(choice)
            if out == True:
                break
         
        print()        
        # Defining parameters for API Request based on choice
        PARAMS, HEADERS = Utilities.logOrRegister(choice) 
        # Make a request to the API
        response = Utilities.MakeRequest(URL, PARAMS, HEADERS, API_Type)       
        # Get data from the API response
        sessionToken, username = Utilities.handleApiResponse(response.json())
        # Determine status of the session
        if sessionToken is None:
            print(notSignedInMessage)
        else:
            print(signedInMessage)
            check_For_Messages = True
            Session(sessionToken, username)
            
        print()
          