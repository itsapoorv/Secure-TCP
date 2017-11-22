# @author: Apoorv Krishak

from twisted.internet.protocol import Protocol, Factory
from twisted.internet.interfaces import ITransport, IStreamServerEndpoint
from playground.network.common.Protocol import StackingTransport,\
    StackingProtocolMixin, StackingFactoryMixin
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import STRING,\
    UINT4, BOOL1, OPTIONAL, DEFAULT_VALUE, LIST
from playground.network.common.Protocol import MessageStorage
from random import randint
from playground.crypto import X509Certificate
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import CertFactory
import sys
import os
from twisted.internet import task, reactor
from time import time

class RIP_Message(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "RIP.RIPMessageID"
    MESSAGE_VERSION = "1.0"
    BODY = [ ("sequence_number", UINT4),
    ("acknowledgement_number", UINT4, OPTIONAL),
    ("signature", STRING, DEFAULT_VALUE("")),
    ("certificate", LIST(STRING), OPTIONAL),
    ("sessionID", STRING),
    ("acknowledgement_flag", BOOL1, DEFAULT_VALUE(False)),
    ("close_flag", BOOL1, DEFAULT_VALUE(False)),
    ("sequence_number_notification_flag", BOOL1, DEFAULT_VALUE(False)),
    ("reset_flag", BOOL1, DEFAULT_VALUE(False)),
    ("data", STRING,DEFAULT_VALUE("")),
    ("OPTIONS", LIST(STRING), OPTIONAL)
    ]


MSS = 4096
#counter = 0

class ProtocolStorage():
    sendBuffer = []
    receiveList = []
    serverSessionID = 0
    clientSessionID = 0
    clientPrivateKey = None
    clientPublicKey = None
    serverPrivateKey = None
    serverPublicKey = None

protocolStorage = ProtocolStorage()

#
#
#
#< RIP Message Functions >
#
#
#



def createMessage(msgType, sequence_number, acknowledgement_number):
    RIP_Msg = RIP_Message()
    RIP_Msg.sequence_number = sequence_number
    RIP_Msg.acknowledgement_number = acknowledgement_number

    if (msgType == "SYN"):
        RIP_Msg.sequence_number_notification_flag = True
    elif (msgType == "SYN-AWK"):
        RIP_Msg.sequence_number_notification_flag = True
        RIP_Msg.acknowledgement_flag = True
    elif (msgType == "AWK"):
        RIP_Msg.acknowledgement_flag = True
    elif (msgType == "RESET"):
        RIP_Msg.reset_flag = True
    elif (msgType == "CLOSE"):
        RIP_Msg.close_flag = True

    return RIP_Msg


def msgType(RIP_Msg):
    if(RIP_Msg.close_flag == True):
        return "CLOSE"
    elif(RIP_Msg.reset_flag == True):
        return "RESET"
    elif(RIP_Msg.sequence_number_notification_flag == True and RIP_Msg.acknowledgement_flag == True):
        return "SYN-AWK"
    elif(RIP_Msg.sequence_number_notification_flag == True and RIP_Msg.acknowledgement_flag == False):
        return "SYN"
    elif(RIP_Msg.sequence_number_notification_flag == False and RIP_Msg.acknowledgement_flag == True):
        return "AWK"
    elif(RIP_Msg.data):
        return "DATA"
    else:
        return "WTF"


def createDataMessage(data):
    RIP_Msg = RIP_Message()
    RIP_Msg.data = data
    #print "createDataMessage(): " + data
    return RIP_Msg


def printMessage(RIP_Msg, type):
    if(type == "summary"):
        print "\t*Message Summary*"
        print "\tType: " + str(msgType(RIP_Msg))
        print "\tSession ID: " + str(RIP_Msg.sessionID)
        print "\tSYN: " + str(RIP_Msg.sequence_number_notification_flag)
        print "\tAWK: " + str(RIP_Msg.acknowledgement_flag)
        print "\tSEQ: " + str(RIP_Msg.sequence_number)
        print "\tACK: " + str(RIP_Msg.acknowledgement_number)
        if (RIP_Msg.data): print "\tDATA: " + str(RIP_Msg.data)
        print ""
    if(type == "sentSummary"):
        print "\t" + "$"*40
        print "\t\t> SENT THE MESSAGE >"
        print "\t\tSession ID: " + str(RIP_Msg.sessionID)
        print "\t\tSEQ: " + str(RIP_Msg.sequence_number)
        print "\t\tACK: " + str(RIP_Msg.acknowledgement_number)
        print "\t\tDATA: " + str(RIP_Msg.data)
        print "\t\tData Length: " + str(len(RIP_Msg.data))
        print "\t" + "$"*40
    if(type == "lineSent"):
        print "\t(SENT)>>> " + "SessionID: " + str(RIP_Msg.sessionID) + " SEQ: " + str(RIP_Msg.sequence_number) + " DATA Length: " + str(len(RIP_Msg.data))
    if(type == "lineReceived"):
        print "(RECV)<<< " + "SessionID: " + str(RIP_Msg.sessionID) + " SEQ: " + str(RIP_Msg.sequence_number) + " DATA Length: " + str(len(RIP_Msg.data))



#
#
#
#</ RIP Message Functions >
#
#
#

#
#
#
#< Protocol Functions >
#
#
#

def validateCertificate(peerCerts):
    peerCerts.append(CertFactory.getRootCert())

    for i in range(0, len(peerCerts)-1):
        thisCert = X509Certificate.loadPEM(peerCerts[i])
        higherCert = X509Certificate.loadPEM(peerCerts[i+1])

        if (thisCert.getIssuer() != higherCert.getSubject()):
            return False
        return True

        higherCertBytes = higherCert.getPublicKeyBlob()
        higherPK = RSA.importKey(higherCertBytes)
        higherVerifier = PKCS1_v1_5.new(higherPK)
        hasher = SHA256.new()
        bytesToVerify = thisCert.getPemEncodedCertWithoutSignatureBlob()
        hasher.update(bytesToVerify)
        if not higherVerifier.verify(hasher, thisCert.getSignatureBlob()):
            print "Certificates not validated."
            return False
    print "Certificates validated successfully."
    return True

def signMessage(msgBytes, privateKey):
    hasher = SHA256.new()
    hasher.update(msgBytes)
    rsaSigner = PKCS1_v1_5.new(privateKey)
    return rsaSigner.sign(hasher)

def verifySignature(msg, peerPublicKey):
    msgSignature = msg.signature
    msg.signature = ""
    hasher = SHA256.new()
    hasher.update(msg.__serialize__())
    rsaVerifier = PKCS1_v1_5.new(peerPublicKey)
    verify = rsaVerifier.verify(hasher, msgSignature)
    return verify



#
#
#
#</ Protocol Functions >
#
#
#

#
#
#
#< STATES >
#
#
#

class State():
    def msgReceived():
        raise NotImplemented

class CLOSED(State):


    def intitalize(self, nonce, transport):
        rawKey = CertFactory.getPrivateKeyForAddr(transport.getHost().host)
        transport.privateKey = RSA.importKey(rawKey)
        protocolStorage.clientPrivateKey = RSA.importKey(rawKey)
        print "\n\t\t< CLOSED >\n"
        ISN = randint(1, 99999999)
        sendMessage = createMessage("SYN", ISN, 0)
        #Certificates
        certChain = CertFactory.getCertsForAddr(transport.getHost().host)
        #print ("Client Certificate: " + str(certChain[0]))
        #print ("CA Certificate: " + str(certChain[1]))
        sendMessage.certificate = [nonce, certChain[0], certChain[1]]
        sendMessage.sessionID = ""
        sendMessage.signature = signMessage(sendMessage.__serialize__(), protocolStorage.clientPrivateKey)
        transport.write(sendMessage.__serialize__())
        print "<CLOSED> SYN Sent"
        print "\n\t\t< SYN_SENT >\n"
        return 1

    def msgReceived():
        return 1

class SYN_SENT(State):
    def msgReceived(self, msg, transport):
        #print "@SYN_SENT.msgReceived()"
        if( msgType(msg) != "SYN-AWK"):
            print "Received: " + msgType(msg) + ". Expecting a SYN-AWK."
            return 0
        else:
            print("<SYN_SENT> Received SYN-AWK")
            printMessage(msg, "summary")
            currentCertificate = X509Certificate.loadPEM(msg.certificate[2])
            currentPublicKeyBlob = currentCertificate.getPublicKeyBlob()
            transport.peerPublicKey = RSA.importKey(currentPublicKeyBlob)
            protocolStorage.serverPublicKey = RSA.importKey(currentPublicKeyBlob)
            self.peerCerts = [msg.certificate[2], msg.certificate[3]]
            if not validateCertificate(self.peerCerts):
                print ("<SYN_SENT> Certificate NOT Verified")
                return 0
            print "<SYN_SENT> Certificate verified."
            sendMessage = createMessage("AWK", msg.acknowledgement_number, msg.sequence_number + 1)
            intNonce = int(msg.certificate[0], 16)
            intNonce = intNonce + 1
            hexNonce = hex(intNonce)
            sendMessage.certificate = [hexNonce]
            #rawKey = CertFactory.getPrivateKeyForAddr("Keys/Client/PrivateKey")
            #rsaKey = RSA.importKey(rawKey)
            #rsaSigner = PKCS1_v1_5.new(rsaKey)
            #hasher = SHA256.new()
            #hasher.update(msg.certificate[0])
            #signedNonce = rsaSigner.sign(hasher)
            sendMessage.sessionID = ""
            sendMessage.signature = signMessage(sendMessage.__serialize__(), protocolStorage.clientPrivateKey)
            transport.write(sendMessage.__serialize__())
            print "<SYN_SENT> Sent AWK"
            #printMessage(sendMessage, "summary")
            transport.SEQ = msg.acknowledgement_number + len(msg.data) + 1
            transport.ACK = msg.sequence_number
            print "\n\t\t< ESTAB >\n"
            return 2

class LISTEN(State):
    def __init__(self, nonce):

        print "\n\t\t< LISTEN >\n"
        self.nonce = nonce

    def msgReceived(self, msg, transport):
        rawKey = CertFactory.getPrivateKeyForAddr(transport.getHost().host)
        transport.privateKey = RSA.importKey(rawKey)
        protocolStorage.serverPrivateKey = RSA.importKey(rawKey)
        if(msgType(msg) != "SYN"):
            print ("<LISTEN> Expecting SYN")
            return 0
        else:
            print "<LISTEN> SYN Received"
            printMessage(msg, "summary")
            currentCertificate = X509Certificate.loadPEM(msg.certificate[1])
            currentPublicKeyBlob = currentCertificate.getPublicKeyBlob()
            transport.peerPublicKey = RSA.importKey(currentPublicKeyBlob)
            protocolStorage.clientPublicKey = RSA.importKey(currentPublicKeyBlob)
            self.peerCerts = [msg.certificate[1], msg.certificate[2]]
            if not validateCertificate(self.peerCerts):
                print ("<LISTEN> Certificate NOT Verified")
                return 0
            print ("<LISTEN> Certificate Verified")
            #Send SYN-AWK

            sequence_number = randint(1, 99999999)
            sendMessage = createMessage("SYN-AWK", sequence_number, msg.sequence_number + 1)
            #print "Cert: " + msg.certificate[0]
            transport.sessionID = str(self.nonce) + str(msg.certificate[0])
            print "SERVER SessionID: " + transport.sessionID
            sendMessage.sessionID = transport.sessionID
            protocolStorage.serverSessionID = transport.sessionID

            certChain = CertFactory.getCertsForAddr(transport.getHost().host)
            intNonce = int(msg.certificate[0], 16)
            intNonce = intNonce + 1
            hexNonce = hex(intNonce)
            sendMessage.certificate = [self.nonce, hexNonce, certChain[0], certChain[1]]

            sendMessage.signature = signMessage(sendMessage.__serialize__(), protocolStorage.serverPrivateKey)

            #print ("Server Certificate: " + str(certChain[0]))
            #print ("CA Certificate: " + str(certChain[1]))

            transport.write(sendMessage.__serialize__())
            print "<LISTEN> Sent SYN-AWK"
            print "\n\t\t< SYN_RECV >\n"
            return 1

class SYN_RECV(State):
    def msgReceived(self, msg, transport):
        if (msgType(msg) != "AWK"):
            print "<SYN_RECV> Error: Expecting AWK"
            return 0
        print "<SYN_RECV> Received AWK"
        printMessage(msg, "summary")
        transport.SEQ = msg.acknowledgement_number + len(msg.data) + 1
        transport.ACK = msg.sequence_number
        print "\n\t\t< ESTAB >\n"
        return 2

class ESTAB(State):
    def msgReceived(self, msg, transport):
        global counter
        if(msgType(msg) != "AWK"):
            #print "<ESTAB> DATA RECEIVED: " + msg.data
            awkMsg = createMessage("AWK", msg.acknowledgement_number+1, msg.sequence_number)
            awkMsg.sessionID = transport.sessionID
            transport.write(awkMsg.__serialize__())
        else:
            #print "-"*39
            print "<ESTAB> Received ACK for SEQ : " + str(msg.acknowledgement_number)

            #counter += 1
            #if(counter%3 == 0):
            #    return 2
            #Update the sendBuffer based on received acknowledgement
            for tup in protocolStorage.sendBuffer:
                if (tup[0] == msg.acknowledgement_number):
                    protocolStorage.sendBuffer.remove(tup)
            #print "-"*39

        return 2


#
#
#
#</ STATES >
#
#
#

#
#
#
#< PROTOCOL CLASSES >
#
#
#

class RIP_Transport(StackingTransport):

    def __init__(self, lowerTransport, transportOf):
        StackingTransport.__init__(self, lowerTransport)
        self.SEQ = 0
        self.ACK = 0
        self.transportOf = transportOf

    def setSessionID(self, sessionID):
        self.sessionID = sessionID

    def chunkData(self, data, MSS):
        if len(data) <= MSS:
            return [data]
        else:
            return [data[:MSS]] + self.chunkData(data.replace(data[:MSS], ''), MSS)

    def write(self, data):
        global MSS
        sendData = self.chunkData(data, MSS)
        #print "Sending... " + str(sendData)
        print self.transportOf
        for dataChunk in sendData:
            sendMessage = createDataMessage(dataChunk)
            sendMessage.sequence_number = self.SEQ
            sendMessage.acknowledgement_number = self.ACK
            if self.transportOf == "server":
                sendMessage.sessionID = protocolStorage.serverSessionID
                sendMessage.signature = signMessage(sendMessage.__serialize__(), protocolStorage.serverPrivateKey)
            else:
                sendMessage.sessionID = protocolStorage.clientSessionID
                sendMessage.signature = signMessage(sendMessage.__serialize__(), protocolStorage.clientPrivateKey)
            self.lowerTransport().write(sendMessage.__serialize__())
            printMessage(sendMessage, "lineSent")
            self.SEQ = self.SEQ + len(sendMessage.data) + 1
            tup = (sendMessage.sequence_number, time(), sendMessage)
            protocolStorage.sendBuffer.append(tup)

        task.deferLater(reactor, 4, self.retransmission)

    def retransmission(self):
        #print protocolStorage.sendBuffer
        for tup in protocolStorage.sendBuffer:
            #print time() - tup[1]
            if ((time() - tup[1]) > 10):
                print "RESENDING > "
                printMessage(tup[2], "lineSent")
                self.lowerTransport().write(tup[2].__serialize__())
        return 0

    def loseConnection(self):
        print "transport.loseConnection()"
        if protocolStorage.sendBuffer:
            task.deferLater(reactor, 2, self.retransmission)
        self.retransmission()
        closePacket = createMessage("CLOSE", self.SEQ, self.ACK)
        if self.transportOf == "server":
            closePacket.sessionID = protocolStorage.serverSessionID
            closePacket.signature = signMessage(closePacket.__serialize__(), protocolStorage.serverPrivateKey)
        else:
            closePacket.sessionID = protocolStorage.clientSessionID
            closePacket.signature = signMessage(closePacket.__serialize__(), protocolStorage.clientPrivateKey)
        print "Sending Close Request To Peer"
        self.lowerTransport().write(closePacket.__serialize__())
        StackingTransport.loseConnection(self)




class RIP_Client(StackingProtocolMixin, Protocol):

    currentState = State()

    def __init__(self):
        print "@RIP_Client.__init__()"
        self.nonce = os.urandom(8).encode('hex')
        #self.nonce = randint(1000, 9999)
        self.storage = MessageStorage()
        self.STATES = [CLOSED(), SYN_SENT(), ESTAB()]

    def connectionMade(self):
        self.higherTransport = RIP_Transport(self.transport, "client")
        self.currentState = self.STATES[self.STATES[0].intitalize(self.nonce, self.transport)] #CLOSED -> SYN_SENT

    def dataReceived(self, data):
        self.storage.update(data)
        try:
            for receivedMessage in self.storage.iterateMessages():
                msg = receivedMessage
                #print ("=="*10 + "\nReceived:\n" + str(printMessage(msg, "summary")))
                if(self.currentState == self.STATES[1]):


                    self.makeHigherConnection(self.higherTransport)
                    self.transport.sessionID = str(self.nonce) + str(msg.certificate[0])
                    print "CLIENT SessionID: " + self.transport.sessionID
                    protocolStorage.clientSessionID = self.transport.sessionID

                self.currentState = self.STATES[self.currentState.msgReceived(msg, self.transport)]
                if(self.currentState == self.STATES[2]):
                    if(msgType(msg) != "AWK"):
                        self.transport.ACK = msg.sequence_number + len(msg.data) + 1
                        printMessage (msg, "lineReceived")
                        if verifySignature(msg, protocolStorage.serverPublicKey):
                            print "Signature Verified"
                            for SEQ in protocolStorage.receiveList:
                                if(msg.sequence_number == SEQ):
                                    print "Duplicate Packet. SEQ: "+ str(msg.sequence_number) + ". Dropping."
                                    return
                            self.higherProtocol() and self.higherProtocol().dataReceived(msg.data)
                            protocolStorage.receiveList.append(msg.sequence_number)
                            if(msgType(msg) == "CLOSE"):
                                print "CLOSE Received"
                                self.higherTransport.closeConnection()
                                self.currentState == self.STATES[0]
                        else:
                            print "Signature Not Verified. Dropping Packet."
                            return

        except Exception, e:
            print "We had an error: ", e
            return





class RIP_Server(StackingProtocolMixin, Protocol):

    currentState = State()

    def __init__(self):
        print "@RIP_Server.__init__()"
        self.nonce = os.urandom(8).encode('hex')
        self.storage = MessageStorage()
        self.STATES = [LISTEN(self.nonce), SYN_RECV(), ESTAB()]

    def connectionMade(self):
        print "@RIP_Server.connectionMade()"
        self.currentState = self.STATES[0]
        self.higherTransport = RIP_Transport(self.transport, "server")

    def dataReceived(self, data):
        self.storage.update(data)
        self.createTransport = False
        try:
            for receivedMessage in self.storage.iterateMessages():
                msg = receivedMessage
                if(self.currentState == self.STATES[1]):
                    self.createTransport = True

                self.currentState = self.STATES[self.currentState.msgReceived(msg, self.transport)]
                if(self.createTransport):

                    self.makeHigherConnection(self.higherTransport)
                    self.createTransport = False
                if(self.currentState == self.STATES[2]):
                    if(msgType(msg) != "AWK"):
                        #print msg.sequence_number
                        self.transport.ACK = msg.sequence_number + len(msg.data) + 1
                        #print "\n" + "("*10 + " Message Received " + ")"*10
                        printMessage (msg, "lineReceived")
                        if verifySignature(msg, protocolStorage.clientPublicKey):
                            print "Signature Verified"
                            for SEQ in protocolStorage.receiveList:
                                if(msg.sequence_number == SEQ):
                                    print "Duplicate Packet. SEQ: "+ str(msg.sequence_number) + ". Dropping."
                                    return
                            self.higherProtocol() and self.higherProtocol().dataReceived(msg.data)
                            protocolStorage.receiveList.append(msg.sequence_number)
                            if(msgType(msg) == "CLOSE"):
                                print "CLOSE Received"
                                self.higherTransport.closeConnection()
                                self.currentState == self.STATES[0]
                        else:
                            print "Signature Not Verified. Dropping Packet."
                            return
        except Exception, e:
            print "We had an error: ", e
            return





class RIP_ConnectFactory(StackingFactoryMixin, Factory):
    protocol = RIP_Client

class RIP_ListenFactory(StackingFactoryMixin, Factory):
    protocol = RIP_Server

#
#
#
#</ PROTOCOL CLASSES >
#
#
#

ConnectFactory = RIP_ConnectFactory
ListenFactory = RIP_ListenFactory
