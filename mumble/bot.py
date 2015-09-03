import sys

from . import packets
from .protocol import MumbleProtocol
from .objects import MumbleUser, MumbleChannel

import protobuf
from twisted.internet import reactor


def placeNew(orig, new):
	if not new:
		return orig
	else:
		return new


class MumbleBot(MumbleProtocol):
	def __init__(self):
		MumbleProtocol.__init__(self)

		self.connected = False
		self.wasConnected = False
		self.inited = False

		self.users = {}
		self.channels = {}

		self.user = MumbleUser()

		self.server_password = None

		self.createHandlers()

	def connectionMade(self):
		if self.wasConnected:
			del self.users[self.session]
			self.wasConnected = False

		self.connected = True
		self.sendVersion()

	def connectionLost(self, reason):
		self.connected = False
		self.wasConnected = True

		print("Protocol disconnected! Reason: %s\n " % reason)
		if len(self.users) <= 0:
			return

	def createHandlers(self):
		handlers = {
			packets.VERSION: self.storeVersion,
			# 1: pass,
			packets.AUTHENTICATE: self.receiveAuth,
			packets.PING: self.receiveHearbeat,
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
			# 25: pass
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
		self.user['self_mute'] = not self.user['self_mute']

	def toggleDeafened(self):
		self.user['self_deaf'] = not self.user['self_deaf']

	def syncState(self):
		self.setState(self.user['channel_id'], self.user['self_mute'], self.user['self_deaf'], self.user['comment'])

	def sendVersion(self):
		local_version = protobuf.Version()
		local_version.version = self.encodeVersion(1, 2, 8)
		local_version.release = "Initial"
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

	def authenticate(self):
		authenticate_packet = protobuf.Authenticate()
		authenticate_packet.username = self.user['name'].encode("UTF-8")
		if self.server_password and len(self.server_password) > 0:
			authenticate_packet.password = self.server_password.encode("UTF-8")
		self.writeProtobuf(2, authenticate_packet)

	def syncWithServer(self, data):
		server_packet = protobuf.ServerSync()
		server_packet.ParseFromString(data)

		self.session = server_packet.session

		self.keepAlive()  # Begin heartbeat

	def acceptConfigs(self, data):
		config_packet = protobuf.ServerConfig()
		config_packet.ParseFromString(data)
		self.max_msg_len = config_packet.message_length

	def encodeVersion(self, major, minor, patch):
		return (major << 16) | (minor << 8) | (patch & 0xFF)

	def keepAlive(self):
		if not self.connected:
			return

		# print("*ping*")

		ping = protobuf.Ping()
		self.writeProtobuf(3, ping)

		reactor.callLater(25, self.keepAlive)

	def receiveHearbeat(self, data):
		pass  # print("*pong*")

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
		# state_packet.actor = self.session
		# state_packet.user_id = self.users[self.session].user_id
		if state_packet.ByteSize() <= 0:
			return

		print("Setting state to:\n%s" % state_packet)
		self.writeProtobuf(9, state_packet)

	def updateUser(self, packet):
		user = self.users[packet.session]
		user['session'] = packet.session
		user['name'] = placeNew(user['name'], packet.name)
		user['user_id'] = placeNew(user['user_id'], packet.user_id)
		user['channel_id'] = placeNew(user['channel_id'], packet.channel_id)
		user['muted'] = placeNew(user['muted'], packet.mute)
		user['deafened'] = placeNew(user['deafened'], packet.deaf)
		user['suppressed'] = placeNew(user['suppressed'], packet.suppress)
		user['self_mute'] = placeNew(user['self_mute'], packet.self_mute)
		user['self_deaf'] = placeNew(user['self_deaf'], packet.self_deaf)
		user['comment'] = placeNew(user['comment'], packet.comment)

	def updateChannel(self, packet):
		channel = self.channels[packet.channel_id]
		channel['channel_id'] = packet.channel_id
		channel['name'] = placeNew(channel['name'], packet.name)
		channel['parent'] = placeNew(channel['parent'], packet.parent)
		channel['description'] = placeNew(channel['description'], packet.description)
		channel['position'] = placeNew(channel['position'], packet.position)

	def checkUser(self, data):
		state_packet = protobuf.UserState()
		state_packet.ParseFromString(data)
		try:
			self.users[state_packet.session]
		except KeyError:
			self.users[state_packet.session] = MumbleUser()

		if (state_packet.channel_id is not None):
			old_channel = self.users[state_packet.session]['channel_id']
			self.updateUser(state_packet)

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
			del self.users[int(state_packet.session)]
		except KeyError:
			print("Could not remove user: %s." % self.users[int(state_packet.session)])
