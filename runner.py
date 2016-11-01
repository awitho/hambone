
# coding=utf-8

import sys

from twisted.internet import reactor
from twisted.internet.ssl import ClientContextFactory
from twisted.internet.protocol import Factory
from twisted.internet.error import ConnectionAborted
from OpenSSL import SSL

import config
import hambone

if sys.version_info[0] >= 3:
	from importlib import reload


class HamboneFactory(Factory):
	def __init__(self):
		pass

	def buildProtocol(self, addr):
		return hambone.Hambone(name=config.name)

	def startedConnecting(self, connector):
		pass

	def clientConnectionFailed(self, connector, reason):
		reactor.stop()

	def clientConnectionLost(self, connector, reason):
		try:
			reason.raiseException()
		except (ConnectionAborted, SSL.Error):
			reactor.stop()
			return
		except:
			reload(hambone)
			connector.connect()


class CtxFactory(ClientContextFactory):
	isClient = 1

	def getContext(self):
		ctx = SSL.Context(SSL.TLSv1_METHOD)
		ctx.use_certificate_file(config.key[0])
		ctx.use_privatekey_file(config.key[1])

		return ctx

if __name__ == "__main__":
	reactor.connectSSL(config.host[0], config.host[1], HamboneFactory(), CtxFactory())
	reactor.run()
