#!/usr/bin/python2.7

import base64
from hashlib import sha256
from threading import Thread
import multiprocessing
import socket
import json
import time
import logging
import binascii
import pickle
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from multiprocessing import Manager
from multiprocessing.managers import BaseManager, BaseProxy
import operator


TARGETHOST = "192.168.138.163"  
LOCALHOST  = "192.168.138.166"  

TCP_RECV_PORT = 9000 
TCP_SEND_PORT = 7000 

DEVICE_REGISTAR_PORT = 6000

BUFFER_SIZE = 4096

class device:  
    def __init__(self, iotdevice_macaddr, publickey):  
        self.iotdevice_macaddr = iotdevice_macaddr  
        self.publickey = publickey


class Block:
    def __init__(self, index, iotdevice_macaddr, publickey, timestamp, previous_hash, proof_hash = 0, nonce = 0):
        self.index = index
        self.iotdevice_macaddr = iotdevice_macaddr
        self.publickey = publickey
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = proof_hash
        self.nonce = nonce


    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()


class Blockchain:
    difficulty = 2

    # Here we Maintian List of unconfirmed and confirmed devices
    def __init__(self):
        self.unconfirmed_devices = []
        self.chain = []
        self.create_genesis_block()


    def create_genesis_block(self):
        genesis_block = Block(0, '0', '0', 0, "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)


    @property
    def last_block(self):
        return self.chain[-1]


    def print_chain(self): 
        for elem in self.unconfirmed_devices:
            for x in elem:
                print("IoT Blockchain: Device ID: ")
                print(x)

        for elem in self.chain:
            print("IoT Blockchain Details: Device ID: ", elem.iotdevice_macaddr)


    # Here we are Checking during Authetication
    #  --- Hence we need to search in confirmed deices List
    def find_device(self, iotdevice_macaddr):
        hashvalue =  dict(); 
        hashvalue['STATUS'] =  "FAILURE"
        hashvalue['PUBLIC_KEY'] = ''

        for elem in self.chain:
            if elem.iotdevice_macaddr == iotdevice_macaddr:
                hashvalue['STATUS'] =  "SUCCESS"
                hashvalue['PUBLIC_KEY'] = elem.publickey
                break;
       
        return hashvalue


    def add_block(self, block, proof):
        previous_hash = self.last_block.previous_hash

        if previous_hash != block.previous_hash:
            return False

        if not Blockchain.is_valid_proof(block, proof):
            return False

        block.hash = proof
        self.chain.append(block)

        for elem in self.chain:
            print("Creating Block with IoT Device ID: ", elem.iotdevice_macaddr)


        print("Added Block to the Blockchain")
        return True


    def mine_device(self):
        if not self.unconfirmed_devices:
            return False

        last_block = self.last_block
        print("Mining the Block containing new IoT device with Device ID:", self.unconfirmed_devices[0].iotdevice_macaddr)

        new_block = Block(index = last_block.index + 1,
                          iotdevice_macaddr = self.unconfirmed_devices[0].iotdevice_macaddr,
                          publickey = self.unconfirmed_devices[0].publickey,
                          timestamp = time.time(),
                          previous_hash = last_block.previous_hash)

        proof = self.proof_of_work(new_block)

        self.add_block(new_block, proof)
	self.unconfirmed_devices.pop(0)

        return True


    @staticmethod
    def proof_of_work(block):
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash


    def device_registration(self, iotdevice_macaddr, publickey):
        self.unconfirmed_devices.append(device(iotdevice_macaddr, publickey))
        print("++++++++++++++++++++++********************++++++++++++++++++++++")
        print("++++++++++++++++++++IoT Device Registration+++++++++++++++++++++")
        print("++++++++++++++++++++++******************* ++++++++++++++++++++++")
        for elem in self.unconfirmed_devices:
            print("Registration Request for IoT Device ID: ", elem.iotdevice_macaddr)

        self.mine_device()


    @classmethod
    def is_valid_proof(cls, block, block_hash):
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())


class blockchain_peers:
    ipaddrlist = [];
 
    @staticmethod
    def add_ipaddress(ipaddr):    
        blockchain_peers.ipaddrlist.append(ipaddr);

    @staticmethod
    def getList():
        return blockchain_peers.ipaddrlist
       

###############################################################################################

'''
Here we are Creating Shared blockchain object which is Shared between Multiple process 
Instances Running on same Node
'''
class MyManager(BaseManager):
        pass

MyManager.register('Blockchain1', Blockchain)
manager = MyManager()
manager.start()
blockchainObj = manager.Blockchain1()

def device_register(jsonrecv):
    if 'DEVICE_CMD' not in jsonrecv:
        raise ValueError("No DEVICE_CMD in given data")
    if 'DEVICE_ID' not in jsonrecv:
        raise ValueError("No DEVICE_ID in given data")
    if 'PUBLIC_KEY' not in jsonrecv:
        raise ValueError("No PUBLIC_KEY in given data")
    
    blockchainObj.device_registration(jsonrecv['DEVICE_ID'], jsonrecv['PUBLIC_KEY'])


def find_iotdevice_blockchain(key):
    blockchainObj.print_chain()
    data = blockchainObj.find_device(key)
    return data
    

'''
Here we are Sending request to peers node to search for device is present 
Response : json filled with RESPONSE : success/failure 
            sucessful json contains public key
'''
def find_iotdevice_blockchain_peers(DEVICE_ID):
    print("++++++++++++++++++++++********************++++++++++++++++++++++")
    print("+++++++++IoT Device Authentication : Peers Search ++++++++++++++")
    print("++++++++++++++++++++++******************* ++++++++++++++++++++++")

    retval = {'STATUS': "FAILURE"}
    peerip_list = blockchain_peers.getList();
    for ip in peerip_list:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                s.connect((TARGETHOST, TCP_SEND_PORT))
                break
            except socket.error:
                print "Connection Failed with FOG node, Retrying ..."
                time.sleep(3)

        connected = True
        print( "CHECK deviceid in Blockchain Network ..." )
        
        register = {
                      "DEVICE_CMD": "SEARCH", 
                      "DEVICE_ID": DEVICE_ID
                   }

        print(register)
        data1 = pickle.dumps(register)

        try:
            s.sendall(data1)
            msgrecv = s.recv(BUFFER_SIZE)
            print("Recieved Message : ", msgrecv)
            if msgrecv:
                if (msgrecv == "NACK") or (msgrecv == "BYE"):
                    s.close();
            else:
                # no more data -- quit the loop
                print ("no more data.")
                s.close();

            jsonrecv = pickle.loads(msgrecv)
            print(jsonrecv)

            if (jsonrecv['STATUS'] == "SUCCESS"):
                return jsonrecv;


        except socket.error:
            print( "Connection lost with  FOG Node ... reconnecting" )

        s.close();

    return retval 


def encrypt_message(a_message , publickey):
    encrypted_msg = publickey.encrypt(a_message, 32)[0]
    encoded_encrypted_msg = base64.b64encode(encrypted_msg) 
    return encoded_encrypted_msg


'''
1. Server maintains the connection with its Peers.
2. Server maintains the connection with its Devices .
3. connection will be used send Information between Nodes of Blockchain.
'''

def send_message(connection, retval):
    msg = "Hello IA693! We had fun learning and creating Blockchain"
    pem = retval['PUBLIC_KEY']
    publickey = RSA.importKey(pem, passphrase=None) 
    encrypted_msg = encrypt_message(msg.encode(), publickey)

    print("Encrypted Message is: ")
    print(encrypted_msg)

    connection.sendall(encrypted_msg)


def device_register_request(connection, address):
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("process-")
    try:
        logger.debug("Recieved DEVICE Registration/Authentication request %r at %r", connection, address)
        received = connection.recv(BUFFER_SIZE).decode("utf-8")
        if received == "":
            logger.debug("Connection closed by DEVICE")
            connection.close()

        jsonrecv = pickle.loads(received)

        if (jsonrecv['DEVICE_CMD'] == "REGISTER"):
            device_register(jsonrecv)

            retval = {}
            counter = 0
            while counter < 3:
            	retval = find_iotdevice_blockchain(jsonrecv['DEVICE_ID'])
                if (retval['STATUS'] == "SUCCESS"):
                    break;

                time.sleep(3)   # Delays for 3 seconds. 
                counter = counter + 1
                            
            if (retval['STATUS'] == "SUCCESS"):
                print("IoT Device Registration SUCCESSFUL")
                connection.sendall("Registration : SUCCESSFUL")
                print("Sending message to IoT Device, encrypted wih IoT Device Public Key")
                send_message(connection, retval)
            elif (retval['STATUS'] == "FAILURE"):
                print("IoT Device Registration Failed")
                connection.sendall("Registration : FAILED")
            else:
                print("UnKnown State reached")
                
        elif (jsonrecv['DEVICE_CMD'] == "AUTHENTICATION"):
            print("++++++++++++++++++++++********************++++++++++++++++++++++")
            print("++++++++++++++++++++IoT Device Authentication ++++++++++++++++++")
            print("++++++++++++++++++++++******************* ++++++++++++++++++++++")
            logger.debug("Recieved Device AUTHENTICATION Request : ", jsonrecv)

            retval = {}
            counter = 0

            while counter < 3:
            	retval = find_iotdevice_blockchain(jsonrecv['DEVICE_ID'])
                print("++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                print(retval.items())
                if (retval['STATUS'] == "SUCCESS"):
                    break;

                time.sleep(3)   # Delays for 3 seconds. 
                counter = counter + 1
                            
            if (retval['STATUS'] == "SUCCESS"):

                connection.sendall("ACK")
                print("DEVICE AUTHENTICATION : Current Node : SUCCESSFULL")
                send_message(connection, retval)

            elif (retval['STATUS'] == "FAILURE"):

                peer_retval = find_iotdevice_blockchain_peers(jsonrecv['DEVICE_ID'])
                if (peer_retval['STATUS'] == "SUCCESS"):
                    connection.sendall("ACK")
                    print("DEVICE AUTHENTICATION : Peer Node : SUCCESSFULL")
                    print("=========================================================")
                    print(peer_retval.items())
                    send_message(connection, peer_retval)

                elif (peer_retval['STATUS'] == "FAILURE"):
                    print("DEVICE AUTHENTICATION : FAILED")
                    connection.sendall("NACK")
                else:
                    print("UnKnown Result from Peer registered nodes")
            else:
                print("UnKnown State reached")
    except:
        logger.exception("Problem handling request")
    finally:
        logger.debug("Closing socket")
        connection.close()



'''
Here we handle the incoming request from peer node to search for deviceid
'''
def handle_incoming_peer_node_request(connection, address):
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("process-")
    try:
        logger.debug("handle_incoming_peer_node_request %r at %r", connection, address)
        received = connection.recv(BUFFER_SIZE).decode("utf-8")
        if received == "":
            logger.debug("Socket closed by device")
            
        jsonrecv = pickle.loads(received)
        print(jsonrecv)

        if (jsonrecv['DEVICE_CMD'] == "SEARCH"):
            retval = find_iotdevice_blockchain(jsonrecv['DEVICE_ID'])
            print(retval.items())
            if (retval['STATUS'] == "SUCCESS"):

                print("DEVICE FOUND : POSITIVE  in current node of blockchain")
                retval = {
                            'STATUS': "SUCCESS", 
                            'DEVICE_ID': jsonrecv['DEVICE_ID'], 
                            'PUBLIC_KEY': retval['PUBLIC_KEY'] 
                          }

                print(retval)
                retvalF = pickle.dumps(retval)
                connection.sendall(retvalF)
            else:
                print("DEVICE FOUND : NEGATIVE  in current node of blockchain")
                retval = {'STATUS': "FAILURE"}
                print(retval)
                retvalF = pickle.dumps(retval)
                connection.sendall(retvalF)

    except:
        logger.exception("Problem handling request")
    finally:
        logger.debug("Closing socket")
        connection.close()


class Server(object):
    def __init__(self, hostname, port):
        import logging
        self.logger = logging.getLogger("server")
        self.hostname = hostname
        self.port = port

    def startUASListen(self):
        self.logger.debug("UAS listening .... ")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.hostname, self.port))
        self.socket.listen(5)

        while True:
            conn, address = self.socket.accept()
            self.logger.debug("Got block chain connection from peer...")
            process = multiprocessing.Process(target=handle_incoming_peer_node_request, 
                                                args=(conn, address))
            process.daemon = True
            process.start()
            self.logger.debug("Started process %r", process)

    def startDEVICEListen(self):
        self.logger.debug("DEVICE REGISTRATION SERVER listening .... ")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.hostname, self.port))
        self.socket.listen(5)

        while True:
            conn, address = self.socket.accept()
            self.logger.debug("Got DEVICE connection")
            process = multiprocessing.Process(target=device_register_request, args=(conn, address))
            process.daemon = True
            process.start()
            self.logger.debug("Started REGISTRATION process %r", process)


def startserver(PORT):
    logging.basicConfig(level=logging.DEBUG)
    server = Server(LOCALHOST, PORT)

    try:
        if PORT == DEVICE_REGISTAR_PORT:
            server.startDEVICEListen()
        elif PORT == TCP_RECV_PORT:
            server.startUASListen()
        else:
            print("We should never be here")
    except:
        logging.exception("Unexpected exception")
    finally:
        logging.info("Shutting down")
        for process in multiprocessing.active_children():
            logging.info("Shutting down process %r", process)
            process.terminate()
            process.join()


###############################################################################################


if __name__ == "__main__":

    obj = blockchain_peers();
    obj.add_ipaddress(TARGETHOST);

  
    p1 = multiprocessing.Process(target=startserver, args=([DEVICE_REGISTAR_PORT]))
    p2 = multiprocessing.Process(target=startserver, args=([TCP_RECV_PORT]))

    p1.start()
    p2.start()

    p1.join()
    p2.join()
