

def getPrivateKeyForAddr(addr):
    addr = str(addr)
    with open("/home/student/certificates/"+addr +".pem") as f:
        return f.read()

def getCertsForAddr(addr):
    addr = str(addr)
    chain = []
    with open("/home/student/certificates/"+addr+"_signed.cert") as f:
        chain.append(f.read())
    parentHost = addr.split(".")
    parentHost = ".".join(parentHost[:-1])
    with open("/home/student/certificates/"+parentHost+"_signed.cert") as f: 
        chain.append(f.read())   
    return chain

def getRootCert():
	return open("/home/student/certificates/20164_signed.cert").read()
