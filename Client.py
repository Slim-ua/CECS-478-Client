# -*- coding: utf-8 -*-
"""
Created on Sun Dec  2 18:24:23 2018

@author: Kyle Jr
"""

#Ideas: 
# Add a delete-all message function. 

import requests, sys, threading, time

#Global Variables
check_For_Messages = False
user_ID = ''
welcomeMenu = "1 = Sign-In || 2 = Register || 3 = View User Info(TEMP DEBUG) || 4 = Exit:\n"
baseURL = "https://www.brivatekeyle.me/api/"

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

def Session(sessionToken):
    global user_ID
    p = threading.Thread(name = 'Pooling', target = Pooling)
    p.start()
    while 1:
        while 1:
            choice = input("1 = View All Messages || 2 = View All Unread Messages || 3 = Post Message || 4 = View Sent Messages || 5 = Delete A Message || 6 = Sign-Out:\n")
            
            # api-endpoint 
            if choice == "1":
                URL = "https://www.brivatekeyle.me/messages" + "/" + username
                API_Type = "get"
                break
            elif choice == "2":
                URL = "https://www.brivatekeyle.me/messages" + "/" + username
                API_Type = "get"
                break
            elif choice == "3":
                URL = "https://www.brivatekeyle.me/messages"
                API_Type = "post"
                break
            elif choice == "4":
                URL = "https://www.brivatekeyle.me/allmessages"
                API_Type = "get"
                break
            elif choice == "5":
                URL = "https://www.brivatekeyle.me/allmessages"
                API_Type = "get"
                break
            elif choice == "6":
                print("\nSigning Out.")
                global check_For_Messages
                check_For_Messages = False
                user_ID = ''
                return
            else:
                print("Invalid Choice.")
    
        print()
        if choice == "1":
            HEADERS = {'x-access-token':sessionToken}
            PARAMS = {}
        elif choice == "2":
             HEADERS = {'x-access-token':sessionToken}
             PARAMS = {}
             #print(username)
        elif choice == "3":
            message = input("Enter your message:\n")
            receiver = input("Enter the receiver:\n")
            HEADERS = {'x-access-token':sessionToken}
            PARAMS = {'sender':username, 'receiver':receiver, 
                      'message':message, 'sender_ID':user_ID}
        elif choice == "4":
            HEADERS = {'x-access-token':sessionToken}
            PARAMS = {}
        elif choice == "5":
            HEADERS = {'x-access-token':sessionToken}
            PARAMS = {}
        
        response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
        #print(response)
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
                    if 'message' in msg:
                        print('Message: ' + msg['message'])
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
                            print('Message: ' + msg['message'])
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
                    if msg['sender_ID'] == user_ID:
                        if 'Message_date' in msg:
                            print('Date: ' + msg['Message_date'])
                        if 'receiver' in msg:
                                print('Sent To: ' + msg['receiver'])
                        if 'message' in msg:
                            print('Message: ' + msg['message'])
                        print()
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
                    if msg['sender_ID'] == user_ID:
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
        print("Welcome to BrivateKeyle Chat")
        while 1:
            choice = input(welcomeMenu)
            # api-endpoint 
            if choice == "1":
                URL = baseURL + "signin"
                API_Type = "post"
                break
            elif choice == "2":
                URL = baseURL + "register"
                API_Type = "post"
                break
            elif choice == "3":
                URL = baseURL + "users/"
                API_Type = "get"
                break
            elif choice == "4":
                print("\nExiting Program.")
                sys.exit()
            else:
                print("Invalid Choice.")
        
         
        print()
          
        # defining a params dict for the parameters to be sent to the API 
        if choice == "1":
            username = input("Please type in username:\n")
            password = input("Please type in password:\n")
            PARAMS = {'name':username, 'password':password}
            HEADERS = {}
        
        if choice == "2":
            username = input("Please create a username:\n")
            password = input("Please create a password:\n")
            PARAMS = {'name':username, 'password':password}
            HEADERS = {}
            
        if choice == "3":
            PARAMS = {}
            HEADERS = {}
    
        response = MakeRequest(URL, PARAMS, HEADERS, API_Type)
        
        data = response.json()
        
        if choice == "1":
            if data['success'] == True:
                print()
                print(data['message'])
                sessionToken = data['token']
                user_ID = data['user_ID']
            else:
                print()
                print(data['message'])
                sessionToken = None
        elif choice == "2":
            #Maybe add a 'success' parameter to check for this, along with a fail case
            if '_id' in data:
                print()
                print("Registration Complete.")
                sessionToken = None
            else:
                print()
                print("Registration Failed.")
                print(data)
                sessionToken = None
        elif choice == "3":
            #Debug list (not final, make private later)
            print(data)
            sessionToken = None
        else:
            print("Invalid Choice.")
            sessionToken = None
        
        if sessionToken is None:
            print("\nCurrently Not Signed In.")
        else:
            print("\nCurrently Signed In.")
            check_For_Messages = True
            Session(sessionToken)
            
        print()
          