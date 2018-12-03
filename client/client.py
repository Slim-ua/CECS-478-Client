# -*- coding: utf-8 -*-
"""
Created on Sun Dec  2 19:20:34 2018

@author: Luisa
"""
import getpass

def register():
    print("Are you registered?")
    answer = input("Y/N: ")
    
    if answer == 'Y' or answer == 'y':
        login()
    else:
        print("Write your username")
        username = input("Username: ")
        print("Write your password")
        password = getpass.getpass("Password:")
        
        
       