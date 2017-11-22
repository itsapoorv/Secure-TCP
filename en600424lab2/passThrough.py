'''
Created on Oct 2016

@author: Apoorv Krishak
apoorv.krishak@gmail.com
'''
# Import playgroundlog to enable logging
from playground import playgroundlog
import logging

from twisted.internet.protocol import Protocol, Factory
from zope.interface.declarations import implements
from twisted.internet.interfaces import ITransport, IStreamServerEndpoint
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.common.Protocol import MessageStorage
from playground.network.message.StandardMessageSpecifiers import STRING
from playground.network.common.Protocol import StackingTransport,\
    StackingProtocolMixin, StackingFactoryMixin

logger = logging.getLogger(__name__)

class PassThroughMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "passThrough.PassThroughMessage"
    MESSAGE_VERSION = "1.0"
    
    BODY = [ ("data", STRING) ]
    

class PassThroughTransport(StackingTransport):
    def __init__(self, lowerTransport):
        StackingTransport.__init__(self, lowerTransport)
        
    def write(self, data):
        ptMessage = PassThroughMessage()
        ptMessage.data = data
        self.lowerTransport().write(ptMessage.__serialize__())    

class PassThroughProtocol(StackingProtocolMixin, Protocol):
    def __init__(self):
        self.storage = MessageStorage()
        
    def connectionMade(self):
        higherTransport = PassThroughTransport(self.transport)
        self.makeHigherConnection(higherTransport)
        
    def dataReceived(self, data):
        self.storage.update(data)
        for msg in self.storage.iterateMessages():
            #process msg
            ptMessage, bytesUsed = PassThroughMessage.Deserialize(data)
        
        data = ptMessage.data
        self.higherProtocol() and self.higherProtocol().dataReceived(data)
        
class PassThroughFactory(StackingFactoryMixin, Factory):
    protocol = PassThroughProtocol
   
# Turn on logging
logctx = playgroundlog.LoggingContext("passThrough")
    
# Uncomment the next line to turn on "packet tracing"
#logctx.doPacketTracing = True
    
playgroundlog.startLogging(logctx)
playgroundlog.UseStdErrHandler(True)

ConnectFactory = PassThroughFactory
ListenFactory = PassThroughFactory
            
