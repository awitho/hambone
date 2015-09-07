import sys
sys.dont_write_bytecode = True
import hambone

from twisted.internet import reactor
from twisted.internet.ssl import ClientContextFactory
from twisted.internet.protocol import Factory
from twisted.internet.error import ConnectionAborted
from OpenSSL import SSL


class HamboneFactory(Factory):
	def __init__(self):
		pass

	def buildProtocol(self, addr):
		return hambone.Hambone()

	def startedConnecting(self, connector):
		pass

	def clientConnectionFailed(self, connector, reason):
		pass

	def clientConnectionLost(self, connector, reason):
		try:
			reason.raiseException()
		except ConnectionAborted:
			reactor.stop()
			return
		except:
			reload(hambone)
			connector.connect()


class CtxFactory(ClientContextFactory):
	def __init__(self):
		pass

	def getContext(self):
		self.method = SSL.SSLv23_METHOD

		ctx = ClientContextFactory.getContext(self)
		ctx.use_certificate_file('keys\client.crt')
		ctx.use_privatekey_file('keys\client.key')

		return ctx

if __name__ == "__main__":
	reactor.connectSSL("shio.moe", 64738, HamboneFactory(), CtxFactory())
	reactor.run()
