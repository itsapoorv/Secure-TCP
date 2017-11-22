'''
Created on Oct 2016

@author: Apoorv Krishak
apoorv.krishak@gmail.com
'''
# Import playgroundlog to enable logging
from playground import playgroundlog
import logging
import CertFactory

from twisted.internet.protocol import Protocol, Factory
from zope.interface.declarations import implements
from twisted.internet.interfaces import ITransport, IStreamServerEndpoint
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.common.Protocol import MessageStorage
from playground.network.message.StandardMessageSpecifiers import STRING, UINT4,\
     LIST, BOOL1, OPTIONAL, DEFAULT_VALUE, UINT1
from playground.network.common.Protocol import StackingTransport,\
    StackingProtocolMixin, StackingFactoryMixin
from playground.network.common import Timer
from playground.network.common.PlaygroundAddress import PlaygroundAddressPair
from twisted.internet.error import ConnectionDone

from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.PublicKey import RSA
from playground.crypto import X509Certificate
from Crypto.Hash import SHA256

import os
import sys

logger = logging.getLogger(__name__)

class RIPMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "RIP.RIPMessage"
    MESSAGE_VERSION = "1.1"

    BODY = [("sequence_number", UINT4),
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


class RIPTransport(StackingTransport):
    def __init__(self, lowerTransport):
        StackingTransport.__init__(self, lowerTransport)
        #The next sequence number to send data, the field should be
        #updated every time a message is sent.
        self.nextSequenceNumber = int(os.urandom(4).encode('hex'), 16)
        #The current session ID, established in the handshake
        self.sessionID = ""
        #A list of the messages sent that have not yet been acknowledged.
        self.unacknowledgedSent = []
        #The maximum segment size
        self.mss = 4096
        #The current state of the RIP
        self.state = "LISTEN"
        #The timeout period before retransmission
        self.timeout = 4
        #The maximum number of messages sent without an ack
        self.maxSent = 256
        #The buffer to hold any messages sent after the 256th message
        self.sendOverflow = []
        #Timeout for idle/wait in protocol
        self.idleTimeout = None
        #Timeout period for idle/wait
        self.idleTimeoutPeriod = 120

    #Write a message, called by higher layer
    def write(self, data):
        if len(data) > self.mss:
            segments = [data[i:i+self.mss] for i in range(0, len(data), self.mss)]
            for segment in segments:
                rMessage = RIPMessage()
                rMessage.data = segment
                self.writeSignedMessage(rMessage, True)

        else:
            rMessage = RIPMessage()
            rMessage.data = data
            self.writeSignedMessage(rMessage, True)


    #Send a signed message.  This can only be used once the connection is established.
    def writeSignedMessage(self, rMessage, shouldRetransmit):
        if self.idleTimeout:
            self.resetTimeout()
        else:
            self.initTimeout()
        rMessage.sequence_number = self.nextSequenceNumber
        rMessage.sessionID = self.sessionID
        rMessage.signature = ""
        unsignedMessage = rMessage.__serialize__()
        sig = self.sign(unsignedMessage)
        rMessage.signature = sig
        sMessage = rMessage.__serialize__()
        if len(rMessage.data) == 0:
            if not rMessage.acknowledgement_flag or rMessage.sequence_number_notification_flag:
                self.nextSequenceNumber = self.nextSequenceNumber + 1
        else:
            self.nextSequenceNumber = self.nextSequenceNumber + len(rMessage.data)

        if len(self.unacknowledgedSent) >= self.maxSent and not rMessage.acknowledgement_flag:
            self.sendOverflow.append((self.nextSequenceNumber, sMessage, shouldRetransmit))
        else:
            self.lowerTransport().write(sMessage)
            if shouldRetransmit:
                callNum = Timer.callLater(self.timeout, self.retransmit, self.nextSequenceNumber, sMessage)
                self.unacknowledgedSent.append([self.nextSequenceNumber, sMessage, callNum])

    #Transmit any messages that were received when the maximum number of sent messages was reached
    def transmitOverflow(self):
        self.sendOverflow.sort()
        while len(self.unacknowledgedSent) < self.maxSent and len(self.sendOverflow) > 0:
            seqNum, sMessage, shouldRetransmit = self.sendOverflow.pop()
            self.lowerTransport().write(sMessage)
            if shouldRetransmit:
                callNum = Timer.callLater(self.timeout, self.retransmit, seqNum, sMessage)
                self.unacknowledgedSent.append([seqNum, sMessage, callNum])

    #Retransmit messages in the retransmittion queue, called by timer
    def retransmit(self, seqNum, sMessage):
        if not self.state == "CLOSED":
            if seqNum in [x[0] for x in self.unacknowledgedSent]:
                i = [x[0] for x in self.unacknowledgedSent].index(seqNum)
                self.unacknowledgedSent[i][2] = Timer.callLater(self.timeout, self.retransmit, seqNum, sMessage)
                logger.debug("RIP--Retransmitting packet %d", seqNum)
                self.lowerTransport().write(sMessage)

    #Process an acknowledgement by removing all cumulative messages from the
    #retransmission queue.
    def processAck(self, rMessage):
        self.unacknowledgedSent.sort()
        found = False
        i = 0
        for f in range(len(self.unacknowledgedSent)):
            if self.unacknowledgedSent[f][0] == rMessage.acknowledgement_number:
                found = True
                i = f
                break
        if found:
            for j in range(i+1):
                self.unacknowledgedSent[j][2].cancel()
            del self.unacknowledgedSent[:i+1]
            logger.debug("RIP--Acknowledging packet %d", rMessage.acknowledgement_number)
        if len(self.sendOverflow) > 0:
            self.transmitOverflow()
        if self.state == "CLOSE-REQ" and len(self.unacknowledgedSent) == 0:
            logger.debug("RIP--Closing connection, all messages acknowledged")
            self.closeConnection()

    #Sign data, helper method for writeSignedMessage
    def sign(self, data):
        rawKey = CertFactory.getPrivateKeyForAddr(self.getHost().host)
        rsaKey = RSA.importKey(rawKey)
        rsaSigner = PKCS1_v1_5.new(rsaKey)
        hasher = SHA256.new()
        hasher.update(data)
        signatureBytes = rsaSigner.sign(hasher)
        return signatureBytes

    #Lose connection, sends close message, waits for acknowledgement to close
    def loseConnection(self):
        logger.debug("RIP--Lose connection sent %d packets left to ack", len(self.unacknowledgedSent))
        rMessage = RIPMessage()
        rMessage.close_flag = True
        self.writeSignedMessage(rMessage, True)
        self.state = "CLOSE-REQ"

    #Closes the connection, called when close message acknowledged
    def closeConnection(self):
        logger.debug("RIP--%s", self.state)
        self.state = "CLOSED"
        StackingTransport.loseConnection(self)
        #self.lowerTransport().loseConnection()

    #Start the idle timeout timer
    def initTimeout(self):
        self.idleTimeout = Timer.callLater(self.idleTimeoutPeriod, self.timeoutExpired)

    #Close the connection due to timeout
    def timeoutExpired(self):
        print "TIMEOUT"
        self.closeConnection()

    #Reset the idle timer due to activity
    def resetTimeout(self):
        self.idleTimeout.cancel()
        self.initTimeout()





#Superclass for the RIP protocol, holds the common methods for the client and server
#Used to prevent code duplication
class RIPSuper():
    def __init__(self):
        #The nonce sent by the RIP
        self.lastNonce = None
        #Storage for received messages
        self.storage = MessageStorage()
        #The higher transport layer
        self.higherTransport = None
        #The peer RIP's public key
        self.peerPublicKey = None
        #The current host, set upon connection made
        self.host = ""
        #Messages received whose preceeding messages have not be received
        self.outOfOrderMessages = []
        #The session ID of the peer RIP, check to prevent replay
        self.expectedSessionId = ""
        #The next sequence number you expect to reveive from the peer RIP
        self.expectPeerSeqNum = ""
        #The maximum number of messages received without an ack
        self.maxRecv = 256

    #Get the host to determine certificates to send
    def setHost(self):
        self.host = self.higherTransport.getHost().host

    #Generate a new 8 byte nonce
    def generate_nonce(self):
        nonce = os.urandom(8).encode('hex')
        self.lastNonce = nonce
        return nonce

    #Gets the signed certs based on the address
    def getSignedCerts(self):
        return CertFactory.getCertsForAddr(self.host)

    #Verify that the certs are legitimate
    def verify_certs(self, certs):
        certs.append(CertFactory.getRootCert())
        for i in range(len(certs)-1):
            if (certs[i].getIssuer() != certs[i+1].getSubject()):
                return False
            # now let's check the signature
            rootPkBytes = certs[i+1].getPublicKeyBlob()
            # use rootPkBytes to get a verifiying RSA key
            rootPublicKey = RSA.importKey(rootPkBytes)
            rootVerifier = PKCS1_v1_5.new(rootPublicKey)
            hasher = SHA256.new()
            bytesToVerify = certs[i].getPemEncodedCertWithoutSignatureBlob()
            hasher.update(bytesToVerify)
            if not rootVerifier.verify(hasher, certs[i].getSignatureBlob()):
                return False
            return True

    #Get the number that should be used to acknowledge
    def getAckNumber(self, rMessage):
        if len(rMessage.data) == 0:
            if not rMessage.acknowledgement_flag or rMessage.sequence_number_notification_flag:
                return rMessage.sequence_number + 1
            else:
                return rMessage.sequence_number
        else:
            return rMessage.sequence_number + len(rMessage.data)

    #Verify the signature of a signed message
    def verifySignedMessage(self, rMessage):
        sig = rMessage.signature
        rMessage.signature = ""
        sMessage = rMessage.__serialize__()

        rsaVerifier = PKCS1_v1_5.new(self.peerPublicKey)
        hasher = SHA256.new()
        hasher.update(sMessage)

        if not rsaVerifier.verify(hasher, sig):
            return False
        return True

    #Send an acknowledgement with the given number
    def sendAck(self, ackNum):
        newRMessage = RIPMessage()
        newRMessage.acknowledgement_number = ackNum
        newRMessage.acknowledgement_flag = True

        self.higherTransport.writeSignedMessage(newRMessage, False)

    #Process and acknowledgement message
    def processAck(self, rMessage):
        if self.verifySignedMessage(rMessage):
            if self.verifySessionID(rMessage.sessionID):
                self.higherTransport.processAck(rMessage)

    #To prevent replay, verify the session id
    def verifySessionID(self, sessId):
        if self.expectedSessionID == sessId:
            return True
        return False

    #Process a data message.  If in order tell higher layer, else save
    def processDataMesage(self, rMessage):
        if self.verifySignedMessage(rMessage):
            if self.verifySessionID(rMessage.sessionID):
                logger.debug("RIP--Processsing data message %d", rMessage.sequence_number)
                data = rMessage.data
                ackNum = self.getAckNumber(rMessage)
                #Message is the next message in order
                if int(rMessage.sequence_number) == self.expectPeerSeqNum:
                    self.expectPeerSeqNum = ackNum
                    if len(data) > 0:
                        self.higherProtocol() and self.higherProtocol().dataReceived(data)
                    self.outOfOrderMessages.sort()
                    #process any out of order messages received
                    while len(self.outOfOrderMessages) > 0:
                        if self.expectPeerSeqNum == self.outOfOrderMessages[0][0]:
                            self.expectPeerSeqNum = self.outOfOrderMessages[0][1]
                            data = self.outOfOrderMessages[0][2]
                            if len(data) > 0:
                                self.higherProtocol() and self.higherProtocol().dataReceived(data)
                            del self.outOfOrderMessages[0]
                        else:
                            break
                    self.sendAck(self.expectPeerSeqNum)

                #This is a retransmitted message
                elif rMessage.sequence_number < self.expectPeerSeqNum:
                    self.sendAck(self.expectPeerSeqNum)
                #Message out of order, save for later
                else:
                    if not len(self.outOfOrderMessages) >= self.maxRecv:
                        if not rMessage.sequence_number in [x[0] for x in self.outOfOrderMessages]:
                            self.outOfOrderMessages.append((rMessage.sequence_number, ackNum, data))

                #If close has been received an all messages processed, close
                if self.higherTransport.state == "CLOSE-RCVD" and len(self.outOfOrderMessages) == 0:
                        logger.debug("%s--All messages processed, closing connection", type(self))
                        logger.debug("%s--%d sent but not acked", type(self), len(self.higherTransport.unacknowledgedSent))
                        self.higherTransport.closeConnection()

    #Defines the common message responses beween the client/server
    def commonDataReceived(self, rMessage):
        #Close flag received, close is sent reguardless of state
        if rMessage.close_flag:
            if self.verifySignedMessage(rMessage):
                if self.verifySessionID(rMessage.sessionID):
                    self.higherTransport.state = "CLOSE-RCVD"
                    ackNum = self.getAckNumber(rMessage)
                    #All messages have been acknowledged
                    if rMessage.sequence_number == self.expectPeerSeqNum:
                        self.sendAck(ackNum)
                        self.higherTransport.closeConnection()
                    else:
                        self.outOfOrderMessages.append((rMessage.sequence_number, ackNum, rMessage.data))


        #Handshake complete
        if self.higherTransport.state == "ESTAB" or self.higherTransport.state == "CLOSE-RCVD" or self.higherTransport.state == "CLOSE-REQ":
            if rMessage.acknowledgement_flag:
                self.processAck(rMessage)

            if len(rMessage.data) > 0:
                #received normal message
                self.processDataMesage(rMessage)





class RIPClient(StackingProtocolMixin, Protocol, RIPSuper):
    def __init__(self):
        RIPSuper.__init__(self)

    #Start the handshake procedure and set the transport
    def connectionMade(self):
        self.higherTransport = RIPTransport(self.transport)
        self.setHost()
        self.startHandshake()

    #Tell the higher layer the connection was closed
    def connectionLost(self, reason=ConnectionDone):
        Protocol.connectionLost(self, reason=reason)
        self.higherProtocol().connectionLost(reason)
        self.higherProtocol().transport=None
        self.setHigherProtocol(None)

    #Send nonce and certs
    def startHandshake(self):
        #Start handshake procedure
        nonce = self.generate_nonce()

        #Get certificates
        certs = self.getSignedCerts()

        rMessage = RIPMessage()
        rMessage.sequence_number_notification_flag = True
        rMessage.certificate = [nonce] + certs

        self.higherTransport.writeSignedMessage(rMessage, True)
        self.higherTransport.state = "SNN-SENT"

    #Continue handshake, verify signed nonce1 and send signed nonce2
    def handshakeResponse(self, rMessage):
        if len(rMessage.certificate) < 4:
            return
        certs = []
        for i in range(2, len(rMessage.certificate)):
            certs.append(X509Certificate.loadPEM(rMessage.certificate[i]))
        peerPublicKeyBlob = certs[0].getPublicKeyBlob()
        self.peerPublicKey = RSA.importKey(peerPublicKeyBlob)
        #Verify Certs
        if self.verify_certs(certs):
            if self.verifySignedMessage(rMessage):
                if rMessage.acknowledgement_flag:
                    self.higherTransport.processAck(rMessage)
                self.expectPeerSeqNum = rMessage.sequence_number
                #Verify Nonce
                intNonce = int(self.lastNonce, 16)
                intNonce = intNonce + 1
                expectedNonce = hex(intNonce)
                if rMessage.certificate[1] == expectedNonce:
                    hexNonce = rMessage.certificate[0]
                    nonce = int(hexNonce,16)
                    responseNonce = nonce + 1
                    responseNonce = hex(responseNonce)
                    self.higherTransport.sessionID = str(self.lastNonce)+str(hexNonce)
                    self.expectedSessionID = str(hexNonce)+str(self.lastNonce)
                    #Message Verified, send response
                    newRMessage = RIPMessage()
                    newRMessage.sequence_number_notification_flag = True
                    newRMessage.acknowledgement_flag = True
                    newRMessage.acknowledgement_number = self.getAckNumber(rMessage)
                    newRMessage.certificate = [responseNonce]
                    self.higherTransport.writeSignedMessage(newRMessage, False)
                    self.makeHigherConnection(self.higherTransport)
                    self.higherTransport.state = "ESTAB"

    #called by lower layer when data received
    def dataReceived(self, data):
        #Get message
        self.storage.update(data)
        for rMessage in self.storage.iterateMessages():
            if isinstance(rMessage, RIPMessage):
                if self.higherTransport.idleTimeout:
                    self.higherTransport.resetTimeout()
                else:
                    self.higherTransport.initTimeout()
                #We are in the handshake
                if rMessage.sequence_number_notification_flag:
                    self.handshakeResponse(rMessage)
                    self.expectPeerSeqNum = self.expectPeerSeqNum + 1
                    continue

                self.commonDataReceived(rMessage)
            else:
                logger.debug("RIPClient ERROR--Processsing data message of type %s", type(rMessage))




class RIPServer(StackingProtocolMixin, Protocol, RIPSuper):
    def __init__(self):
        RIPSuper.__init__(self)

    #Set transport
    def connectionMade(self):
        self.higherTransport = RIPTransport(self.transport)
        self.setHost()

    #Tell the higher protocol the connection was lost
    def connectionLost(self, reason=ConnectionDone):
        Protocol.connectionLost(self, reason=reason)
        self.higherProtocol().connectionLost(reason)
        self.higherProtocol().transport=None
        self.setHigherProtocol(None)

    #Sign nonce1, send certs and nonce2
    def handshakeInitResponse(self, rMessage):

        if len(rMessage.certificate) < 3:
            return
        certs = []
        for i in range(1, len(rMessage.certificate)):
            certs.append(X509Certificate.loadPEM(rMessage.certificate[i]))
        peerPublicKeyBlob = certs[0].getPublicKeyBlob()
        self.peerPublicKey = RSA.importKey(peerPublicKeyBlob)

        #Verify certificates
        if self.verify_certs(certs):
            if self.verifySignedMessage(rMessage):

                self.expectPeerSeqNum = rMessage.sequence_number
                nonce = rMessage.certificate[0]
                newNonce = self.generate_nonce()

                self.higherTransport.sessionID = str(newNonce)+str(nonce)
                self.expectedSessionID = str(nonce)+str(newNonce)

                intNonce = int(nonce, 16)
                intNonce = intNonce + 1
                hexNonce = hex(intNonce)

                #Get certificates
                certs = self.getSignedCerts()

                #Create response
                newRMessage = RIPMessage()
                newRMessage.sequence_number_notification_flag = True
                newRMessage.acknowledgement_flag = True
                newRMessage.acknowledgement_number = self.getAckNumber(rMessage)
                newRMessage.certificate = [newNonce, hexNonce] + certs

                #Send response
                self.higherTransport.writeSignedMessage(newRMessage, True)
                self.higherTransport.state = "SNN-RECV"


    #Verify signed nonce, send ack, move to estab, inform higher layer
    def completeHandshake(self, rMessage):
        if self.verifySignedMessage(rMessage):
            if self.verifySessionID(rMessage.sessionID):
                if rMessage.acknowledgement_flag:
                    self.higherTransport.processAck(rMessage)
                #Verify Nonce
                intNonce = int(self.lastNonce, 16)
                intNonce = intNonce + 1
                expectedNonce = hex(intNonce)
                if rMessage.certificate[0]== expectedNonce:
                    #Create response
                    newRMessage = RIPMessage()
                    newRMessage.acknowledgement_flag = True
                    newRMessage.acknowledgement_number = self.getAckNumber(rMessage)

                    #Send response
                    self.higherTransport.writeSignedMessage(newRMessage, False)
                    self.higherTransport.state = "ESTAB"
                    self.makeHigherConnection(self.higherTransport)


    def dataReceived(self, data):
        #Get the message
        self.storage.update(data)
        for rMessage in self.storage.iterateMessages():
            if isinstance(rMessage, RIPMessage):
                if self.higherTransport.idleTimeout:
                    self.higherTransport.resetTimeout()
                else:
                    self.higherTransport.initTimeout()
                #In handshake
                if rMessage.sequence_number_notification_flag:
                    if self.higherTransport.state == "LISTEN":
                        self.handshakeInitResponse(rMessage)
                        self.expectPeerSeqNum = self.expectPeerSeqNum + 1
                        continue

                    elif self.higherTransport.state == "SNN-RECV":
                        self.completeHandshake(rMessage)
                        self.expectPeerSeqNum = self.expectPeerSeqNum + 1
                        continue
                    else:
                        if self.verifySignedMessage(rMessage):
                            logger.debug("RIPClient ERROR--Received unexpected SNN, moving to questioning state and closing connection")
                            print "RIPClient ERROR--Received unexpected SNN, moving to questioning state and closing connection"
                            self.higherTransport.state == "QUESTIONING"
                            self.higherTransport.closeConnection()

                else:
                    self.commonDataReceived(rMessage)
            else:
                logger.debug("RIPServer ERROR--Processsing data message of type %s", type(rMessage))

class RIPClientFactory(StackingFactoryMixin, Factory):
    protocol = RIPClient

class RIPServerFactory(StackingFactoryMixin, Factory):
    protocol = RIPServer


# Turn on logging
logctx = playgroundlog.LoggingContext("RIP")

# Uncomment the next line to turn on "packet tracing"
#logctx.doPacketTracing = True

#playgroundlog.startLogging(logctx)
#playgroundlog.UseStdErrHandler(True)

ConnectFactory = RIPClientFactory
ListenFactory = RIPServerFactory
