# -*- coding: utf-8 -*-
"""
Example how username and password works in a database

This python file we are hashing a password in order to store it in a database (dictionary). In this python module we
are using a salt.

A salt is a random sequence added to the password string before using the hash function. The salt is used in order to
prevent dictionary attacks and table attacks.

Hash Functions are used inside some cryptographic algorithms, in digital signatures, message authentication codes,
manipulation detection, fingerprints, checksums, hashtables, password storage (like in this script), etc...

Some of the most used hash functions are:

• MD5: 128 bit hash value
• SHA: The message length rates from 160bits to 512 bits (This python module uses SHA256)

Example:
    When you create an account in a service (e.g. social network), in most common cases the password you choose gets
    encrypted in the database in two sections, the password in itself encrypted with an algorythim like MD5 or SHA and
    a salt.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
   
"""

import uuid
import hashlib

__author__ = 'fedeg'



def data_base():
    """
    Returns:
        an empty dictionary to work as a "database" to the users and passwords

    """
    return {}


def hash_password(passw):
    """

    Args:
     passw (string): the password to be encrypted

    Returns:
        the password encrypted with a salt

    """

    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + passw.encode()).hexdigest() + ':' + salt


def create_user(database):
    """
    Args:
        database: The database where every user and its password will be save it

    """
    print 'Hi, let\'s create a new account!'

    username = None

    while username not in database:
        try:
            username = raw_input('Your username: ')
        except ValueError:
            print 'Error'
            exit()
        if username in database:
            print 'Choose another username, %s it\'s already used.' % username
            username = None
        else:
            database[username] = ''
            try:
                password = raw_input('Your Password: ')
            except ValueError:
                print 'Error'
                exit()
            database[username] = hash_password(password)



def check_password(database, username, userpassword):
    """

    Args:
        database: A database that contains users and its passwords.
        username: The username of the user to be check
        userpassword: The password that the user entered.

    Returns:
        True if the original password matches with the password that the user entered before or False if the original
    password doesn't match with the password that the user entered before

    """
    password, salt = database[username].split(':')
    return password == hashlib.sha256(salt.encode() + userpassword.encode()).hexdigest()


def login(database):
    """
    
    This function will allow to login in the "system"

    Args:
        database: A database that contains users and its passwords.

    """
    username = raw_input('Username: ')
    if username in database:
        password = raw_input('Password: ')
        result = check_password(database, username, password)

        if result:
            print 'Hi %s' %username
            home()
        else:
            print 'Wrong username or password'


def home():
    """
    A simple function to print some welcome message

    """
    print 'Welcome to your Google Calendar'
    for i in range(7):
        print '*',

if __name__ == '__main__':

    database = data_base()

    create_user(database)

    create_user(database)

    login(database)
