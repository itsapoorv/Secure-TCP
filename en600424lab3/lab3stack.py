from RIPDir.RIP import RIPClientFactory
from RIPDir.RIP import RIPServerFactory
from KISS import KissFactory

ConnectFactory = RIPClientFactory.StackType(KissFactory)
ListenFactory = RIPServerFactory.StackType(KissFactory)

