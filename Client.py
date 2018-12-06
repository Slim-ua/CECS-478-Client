# -*- coding: utf-8 -*-
"""
Created on Sun Dec  2 18:24:23 2018

@author: Kyle Jr
"""

#Ideas: 
# Add a delete-all message function. 

import requests, sys, threading, time
from Utilities import *

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
    global user_ID
    while check_For_Messages == True:
        URL = "https://www.brivatekeyle.me/allmessages"
        API_Type = "get"
        HEADERS = {'x-access-token':sessionToken}
        PARAMS = {}
        response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
        data = response.json()
        for msg in data:
            if msg["status"] == 'New' and msg["sender_ID"] != user_ID:
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
    global user_ID
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
        # Determine HTTP headers and parameters based on previous choice on menu
        HEADERS, PARAMS = logedInAction(choice, sessionToken, username)     
        # Make API request
        response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
        data = response.json()
        
        if choice == "1":
            viewAllMessagesManager(data, sessionToken)        
            
        elif choice == "2":
            viewAllUnreadMessagesManager(data, sessionToken)    
                            
        elif choice == "3":
            print(data['message'])
            
        elif choice == "4":
            viewSentMessages(data, sessionToken, username)

        elif choice == "5":
            deleteAMessage(data, sessionToken, username)
            '''amount = 0
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
                            print('Message: ' + msg['message'])
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
                            if data[delete_Numb]['sender_ID'] == user_ID:
                                URL = "https://www.brivatekeyle.me/message/" + data[delete_Numb]['_id']
                                API_Type = "delete"
                                HEADERS = {'x-access-token':sessionToken}
                                PARAMS = {}
                                MakeRequest(URL, PARAMS, HEADERS, API_Type)
                                print('Message Deleted Successfully.')
                                break
                            else:
                                print('Invalid Message Selection.')'''
            
        else:
            print("Invalid Choice.")
        print()
    

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
          