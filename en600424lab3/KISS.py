'''
Created on Oct 2016

@author: Apoorv Krishak
apoorv.krishak@gmail.com
'''

from Crypto.Cipher import AES
from Crypto.Util import Counter

import CertFactory

from twisted.internet.protocol import Protocol, Factory
from zope.interface.declarations import implements
from twisted.internet.interfaces import ITransport, IStreamServerEndpoint
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.common.Protocol import MessageStorage
from playground.network.message.StandardMessageSpecifiers import STRING
from playground.network.common.Protocol import StackingTransport,\
    StackingProtocolMixin, StackingFactoryMixin
from playground.network.common import SimpleMessageHandler

from playground.network.common.PlaygroundAddress import PlaygroundAddressPair
from playground.crypto.PkiPlaygroundAddressPair import PkiPlaygroundAddressPair

from twisted.internet.error import ConnectionDone

from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.PublicKey import RSA
from playground.crypto import X509Certificate
from Crypto.Hash import SHA256

import os

class KissHandshake(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "KissHandShake"
    MESSAGE_VERSION = "1.0"
    BODY = [("key",STRING), 
            ("IV", STRING)]

class KissData(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "KissData"
    MESSAGE_VERSION = "1.0"
    BODY = [("data", STRING)]


class KissAES:
    def __init__(self):
        self.Encryptor = None
        self.Decrpytor = None

    def encryption(self, Text, WriteIV = None, WriteKey = None):
        if WriteIV != None and WriteKey != None:
            IV_asCtr = Counter.new(128, initial_value=int(WriteIV.encode('hex'),16))
            self.Encryptor = AES.new(WriteKey, counter=IV_asCtr, mode=AES.MODE_CTR)
        return self.Encryptor.encrypt(Text)
                
    def decryption(self, Text, ReadIV = None, ReadKey = None):
        if ReadIV != None and ReadKey != None:
            IV_asCtr = Counter.new(128, initial_value=int(ReadIV.encode('hex'),16))
            self.Decryptor = AES.new(ReadKey, counter=IV_asCtr, mode=AES.MODE_CTR)
        return self.Decryptor.decrypt(Text)

        

class KissTransport(StackingTransport):
    def __init__(self, lowerTransport, IV, writeKey):
        StackingTransport.__init__(self, lowerTransport)
        self.IV = IV
        self.writeKey = writeKey
        self.AES = None

    def write(self, data):
        if isinstance(data, KissHandshake):
           self.lowerTransport().write(data.__serialize__())
        else:
            sendData = KissData()
            if not self.AES:
                self.AES = KissAES()
                sendData.data = self.AES.encryption(data, self.IV, self.writeKey)
            else:    
                sendData.data = self.AES.encryption(data)
            self.lowerTransport().write(sendData.__serialize__())


class KissProtocol(StackingProtocolMixin, Protocol):
    def __init__(self):
        #Storage for received messages
        self.storage = MessageStorage()
        #The higher transport layer
        self.higherTransport = None

        self.messageHandler = SimpleMessageHandler()
        self.messageHandler.registerMessageHandler(KissHandshake, self.handshakeMessageHandler)
        self.messageHandler.registerMessageHandler(KissData, self.dataMessageHandler)

        self.readKey = None
        self.readIV = None
        self.AES = None

    #Start the handshake procedure and set the transport    
    def connectionMade(self):
        key = self.generateKey()
        IV = self.generateIV()
        self.higherTransport = KissTransport(self.transport, IV, key)
        self.sendHandshakeMethod(key, IV)

    #Tell the higher layer the connection was closed
    def connectionLost(self, reason=ConnectionDone):
        Protocol.connectionLost(self, reason=reason)
        self.higherProtocol().connectionLost(reason)
        self.higherProtocol().transport=None
        self.setHigherProtocol(None)

    def sendHandshakeMethod(self, key, IV):
        handshakeMessage = KissHandshake()
        encryptedKey, encryptedIV = self.encrpytHandshake(key, IV)
        handshakeMessage.key = encryptedKey
        handshakeMessage.IV = encryptedIV
        self.higherTransport.write(handshakeMessage)

    def generateKey(self):
        return os.urandom(32)

    def generateIV(self):
        return os.urandom(16)

    def dataReceived(self, data):
        self.storage.update(data)
        for msg in self.storage.iterateMessages():
            self.messageHandler.handleMessage(KissProtocol, msg)
            

    def handshakeMessageHandler(self, protocol, msg):
        key, IV = self.decrpytHandshake(msg.key, msg.IV)
        self.readKey = key
        self.readIV = IV
        self.makeHigherConnection(self.higherTransport)    

    def dataMessageHandler(self, protocol, msg):
        encryptedData = msg.data
        if not self.AES:
            self.AES = KissAES()
            data = self.AES.decryption(encryptedData, self.readIV, self.readKey)
        else:
            data = self.AES.decryption(encryptedData)
        self.higherProtocol() and self.higherProtocol().dataReceived(data)

    def decrpytHandshake(self,key, IV):
        pki = self.higherTransport.getHost()
        rsaDecrypter = PKCS1OAEP_Cipher(pki.privateKey, None, None, None)
        return rsaDecrypter.decrypt(key), rsaDecrypter.decrypt(IV)

    def encrpytHandshake(self,key, IV):
        pki = self.higherTransport.getPeer()
        certs = pki.certificateChain
        peerPublicKeyBytes = certs[0].getPublicKeyBlob()
        peerPublicKey = RSA.importKey(peerPublicKeyBytes)
        peerRsaEncrypter = PKCS1OAEP_Cipher(peerPublicKey, None, None, None)
        return peerRsaEncrypter.encrypt(key), peerRsaEncrypter.encrypt(IV)

class KissFactory(StackingFactoryMixin, Factory):
    protocol = KissProtocol


ConnectFactory = KissFactory
ListenFactory = KissFactory
