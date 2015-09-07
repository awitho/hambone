import sys
import struct
import logging

from . import packets
from .protocol import MumbleProtocol
from .objects import MumbleUser, MumbleChannel

import protobuf
from twisted.internet import reactor


class MumbleHandler(logging.Handler):
	def __init__(self, protocol, *args, **kwargs):
		logging.Handler.__init__(self, *args, **kwargs)
		self.protocol = protocol

	def emit(self, record):
		try:
			msg = self.format(record).replace("\n", "<br/>")
			if 'last_message' in self.protocol.user['data']:
				self.protocol.sendToProper(self.protocol.user['data']['last_message'], msg)
			else:
				self.protocol.sendMessageToChannel(self.protocol.user['channel_id'], msg)
		except:
			self.handlerError(record)


def bytearrayToBinaryString(array):
	s = ""
	for c in array:
		s = s + '{0:08b} '.format(c, 'b')
	return s


class MumbleBot(MumbleProtocol):
	format = logging.Formatter("%(asctime)-15s %(name)-3s | %(levelname)-6s: %(message)s")
	s_format = logging.Formatter("%(levelname)s: %(message)s")

	def __init__(self, name, *args, **kwargs):
		MumbleProtocol.__init__(self, *args, **kwargs)

		self.connected = False
		self.wasConnected = False

		self.heartbeat = self.addHandler(packets.PING, self.receiveHearbeat)

		self.users = {}
		self.channels = {}

		self.name = name

		self.server_password = None

		self.createHandlers()

		self.logger = logging.getLogger("hambone")
		if self.logger.handlers == []:
			self.logger.setLevel(logging.DEBUG)

			file = logging.FileHandler("hambone.log")
			file.setLevel(logging.WARNING)
			file.setFormatter(self.format)
			self.logger.addHandler(file)

			console = logging.StreamHandler()
			console.setFormatter(self.format)
			self.logger.addHandler(console)

			mumble = MumbleHandler(self)
			mumble.setFormatter(self.s_format)
			mumble.setLevel(logging.WARNING)
			self.logger.addHandler(mumble)

	def connectionMade(self):
		if self.wasConnected:
			del self.users[self.session]
			self.wasConnected = False

		self.connected = True
		self.sendVersion()

	def connectionLost(self, reason):
		self.connected = False
		self.wasConnected = True

		self.logger.info("Protocol disconnected! Reason:\n%s " % reason.getTraceback())
		if len(self.users) <= 0:
			return

	def createHandlers(self):
		handlers = {
			packets.VERSION: self.storeVersion,
			# 1: pass,
			packets.AUTHENTICATE: self.receiveAuth,
			# packets.PING: self.receiveHearbeat,
			packets.REJECT: self.throwRejection,
			packets.SERVERSYNC: self.syncWithServer,
			# 6: pass,
			packets.CHANNELSTATE: self.checkChannel,
			packets.USERREMOVE: self.removeUser,
			packets.USERSTATE: self.checkUser,
			# 10: pass,
			# packets.TEXTMESSAGE: pass,
			# packets.PERMISSIONDENIED: pass
			# 13: pass,
			# 14: pass,
			packets.CRYPTSETUP: self.setupAuth,
			# 16: pass,
			# 17: pass,
			# 18: pass,
			# 19: pass,
			# 20: pass,
			# 21: pass,
			# 22: pass,
			# 23: pass,
			packets.SERVERCONFIG: self.acceptConfigs,
			packets.SUGGESTCONFIG: self.suggestedConfig,
		}

		for ptype in handlers.keys():
			self.addHandler(ptype, handlers[ptype])

	def setUsername(self, name):
		self.user['name'] = name

	def setComment(self, text):
		self.user['comment'] = text

	def setChannel(self, channel_id):
		self.user['channel_id'] = channel_id

	def toggleMute(self):
		state_packet = protobuf.UserState()
		state_packet.self_mute = not self.user['self_mute']
		state_packet.session = self.session
		self.writeProtobuf(packets.USERSTATE, state_packet)

	def toggleDeafened(self):
		state_packet = protobuf.UserState()
		state_packet.self_deaf = not self.user['self_deaf']
		state_packet.session = self.session
		self.writeProtobuf(packets.USERSTATE, state_packet)

	def syncState(self):
		self.writeProtobuf(packets.USERSTATE, self.user.to_protobuf())

	def sendVersion(self):
		local_version = protobuf.Version()
		local_version.version = self.encodeVersion(1, 2, 10)
		local_version.release = "1.2.10"
		local_version.os = "Python"
		local_version.os_version = str(sys.version_info.major) + "." + str(sys.version_info.minor) + "." + str(sys.version_info.micro)  # sys.version_info

		self.writeProtobuf(0, local_version)

	def storeVersion(self, data):
		self.remote_version = protobuf.Version()
		self.remote_version.ParseFromString(data)

		self.authenticate()

	def receiveAuth(self, data):
		pass

	def setupAuth(self, data):
		auth_packet = protobuf.CryptSetup()
		auth_packet.ParseFromString(data)

		self.key = auth_packet.key
		self.client_nonce = auth_packet.client_nonce
		self.server_nonce = auth_packet.server_nonce

	def authenticate(self):
		authenticate_packet = protobuf.Authenticate()
		authenticate_packet.username = self.name.encode("UTF-8")
		if self.server_password and len(self.server_password) > 0:
			authenticate_packet.password = self.server_password.encode("UTF-8")
		self.writeProtobuf(2, authenticate_packet)

	def syncWithServer(self, data):
		server_packet = protobuf.ServerSync()
		server_packet.ParseFromString(data)

		self.session = server_packet.session
		self.user = self.users[self.session]

		self.addHandler(packets.TEXTMESSAGE, self.logLast)

		self.keepAlive()  # Begin heartbeat

	def logLast(self, data):
		msg_packet = protobuf.TextMessage()
		msg_packet.ParseFromString(data)
		self.user['data']['last_message'] = msg_packet

	def acceptConfigs(self, data):
		config_packet = protobuf.ServerConfig()
		config_packet.ParseFromString(data)
		self.max_msg_len = config_packet.message_length

	def encodeVersion(self, major, minor, patch):
		return (major << 16) | (minor << 8) | (patch & 0xFF)

	def decodeVersion(self, version):
		return (version & ~0x0000FFFF) >> 16, (version & ~0xFFFF00FF) >> 8, (version & ~0xFFFFFF00)

	def keepAlive(self):
		if not self.connected:
			return

		ping = protobuf.Ping()
		self.writeProtobuf(3, ping)

		reactor.callLater(25, self.keepAlive)

	def firstHeartbeat(self, data):
		pass

	def receiveHearbeat(self, data):
		self.removeHandler(packets.PING, self.heartbeat)
		del self.heartbeat
		self.firstHeartbeat(data)

	def throwRejection(self, data):
		pass

	def setState(self, channel_id, muted, deafened, comment):
		state_packet = protobuf.UserState()

		if channel_id:
			state_packet.channel_id = channel_id

		if muted:
			state_packet.self_mute = muted

		if deafened:
			state_packet.self_deaf = deafened

		if comment:
			state_packet.comment = comment

		state_packet.session = self.session
		if state_packet.ByteSize() <= 0:
			return

		self.writeProtobuf(9, state_packet)

	def updateUser(self, packet):
		user = self.users[packet.session]
		user.from_protobuf(packet)

	def updateChannel(self, packet):
		channel = self.channels[packet.channel_id]
		channel.from_protobuf(packet)

	def userJoined(self, data):
		pass

	def userLeft(self, data):
		pass

	def checkUser(self, data):
		state_packet = protobuf.UserState()
		state_packet.ParseFromString(data)
		first = False
		try:
			self.users[state_packet.session]
		except KeyError:
			self.users[state_packet.session] = MumbleUser()
			first = True

		self.updateUser(state_packet)
		if first:
			self.userJoined(self.users[int(state_packet.session)])

	def checkChannel(self, data):
		state_packet = protobuf.ChannelState()
		state_packet.ParseFromString(data)
		try:
			self.channels[state_packet.channel_id]
		except KeyError:
			self.channels[state_packet.channel_id] = MumbleChannel()
		self.updateChannel(state_packet)

	def findUser(self, name):
		# todo: list comprehension.
		for (session, user) in list(self.users.items()):
			if user['name'].find(name) == 0:
				return user['session']
		return -1

	def removeUser(self, data):
		state_packet = protobuf.UserRemove()
		state_packet.ParseFromString(data)
		if (state_packet.session == self.session):
			return
		try:
			self.userLeft(self.users[int(state_packet.session)])
			del self.users[int(state_packet.session)]
		except KeyError:
			self.logger.error("Could not remove user: %s." % self.users[int(state_packet.session)])

	def sendMessageToChannel(self, channel, msg):
		self.logger.debug("Sending message to channel %i:\n\t%s." % (channel, msg))
		msg_packet = protobuf.TextMessage()
		msg_packet.actor = self.session
		msg_packet.channel_id.append(channel)
		msg_packet.message = str(msg)
		self.writeProtobuf(11, msg_packet)

	def sendMessageToUser(self, user, msg):
		self.logger.debug("Sending message to user %i:\n\t%s." % (user, msg))
		msg_packet = protobuf.TextMessage()
		msg_packet.actor = self.session
		msg_packet.session.append(user)
		msg_packet.message = str(msg)
		self.writeProtobuf(11, msg_packet)

	def suggestedConfig(self, data):
		sug_packet = protobuf.SuggestConfig()
		sug_packet.ParseFromString(data)

		t = self.decodeVersion(sug_packet.version) + (sug_packet.positional, sug_packet.push_to_talk,)
		self.logger.debug("Server suggests version: %i.%i.%i, positional: %s and ptt: %s" % t)
