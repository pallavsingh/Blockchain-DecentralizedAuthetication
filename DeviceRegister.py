#!/usr/bin/python2.7

import base64
import re, uuid 
import hashlib
import socket
import json
import time
import logging
import binascii
import pickle
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


DEVICE_ID  = ':'.join(re.findall('..', '%012x' % uuid.getnode()))

TARGETHOST1 = "192.168.138.163"  
TARGETHOST2 = "192.168.138.166"  

DEVICE_REGISTAR_PORT1 = 6000
DEVICE_REGISTAR_PORT2 = 6000

BUFFER_SIZE = 4096 

def generate_keys():
	# RSA modulus length must be a multiple of 256 and >= 1024
	modulus_length = 256*4 # use larger value in production
	privatekey = RSA.generate(modulus_length, Random.new().read)
	publickey = privatekey.publickey()
	return privatekey, publickey


def encrypt_message(a_message , publickey):
	encrypted_msg = publickey.encrypt(a_message, 32)[0]
	encoded_encrypted_msg = base64.b64encode(encrypted_msg) # base64 encoded strings are database friendly
	return encoded_encrypted_msg


def decrypt_message(encoded_encrypted_msg, privatekey):
	decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
	decoded_decrypted_msg = privatekey.decrypt(decoded_encrypted_msg)
	return decoded_decrypted_msg


privatekey = ""
publickey = ""


def send_data(data, s):
    s.sendall(data)
    msgrecv1 = s.recv(BUFFER_SIZE)
    print("Received Message - Normal : ", msgrecv1)
    if msgrecv1:
        if (msgrecv1 == "NACK") or (msgrecv1 == "BYE"):
            s.close();
    else:
        print ("no more data.")
        s.close();


    msgrecv2 = s.recv(BUFFER_SIZE)
    print("Received Message - Encrypted : ", msgrecv2)
    if msgrecv2:
        if (msgrecv2 == "NACK") or (msgrecv2 == "BYE"):
            s.close();
    else:
        print ("no more data.")
        s.close();

    decrypted_msg = decrypt_message(msgrecv2, privatekey)
    print "Decrypted message: %s - (%d)" % (decrypted_msg, len(decrypted_msg))


def connect_socket(ipaddress, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            s.connect((ipaddress, port)) 
            break
        except socket.error:
            print "Connection Failed with FOG node, Retrying ..."
            time.sleep(3)

    return s


'''
1. Device Registration --->>> will send the DeviceId and Public key
'''
def device_registration(ipaddress, port):
    s =  connect_socket(ipaddress, port) 
    print( "REGISTERATION : SUCCESFULL connection to FOG Node ..." )

    global privatekey
    global publickey

    privatekey, publickey = generate_keys()

    register = {"DEVICE_CMD": "REGISTER", 
                "DEVICE_ID": DEVICE_ID, 
                "PUBLIC_KEY" : publickey.exportKey(format='PEM', passphrase=None, pkcs=1)} 

    data = pickle.dumps(register)

    try:
        send_data(data, s)
    except socket.error:
        print( "connection lost with  FOG Node ... reconnecting" )

    s.close();


'''
1. Device Authetication  --->>> will send the DeviceId 
'''
def device_authetication(ipaddress, port):
    s =  connect_socket(ipaddress, port) 
    print( "AUTHENTICATION : SUCCESFULL connection FOG Node ..." )

    authetication = {"DEVICE_CMD": "AUTHENTICATION", 
                     "DEVICE_ID": DEVICE_ID} 
    data = pickle.dumps(authetication)

    try:
        send_data(data, s)
    except socket.error:
        print ("connection lost with  FOG Node ... " )

    s.close();


def samenode_register_authentication():
    device_registration(TARGETHOST1, DEVICE_REGISTAR_PORT1)
    device_authetication(TARGETHOST1, DEVICE_REGISTAR_PORT1)


def peernode_register_authentication():
    device_registration(TARGETHOST1, DEVICE_REGISTAR_PORT1)
    device_authetication(TARGETHOST2, DEVICE_REGISTAR_PORT2)


if __name__ == "__main__":

    print("Calling Device Registration Function : ")
    print("IoT Device ID: ", DEVICE_ID)

    #samenode_register_authentication()
    peernode_register_authentication()
