import re
import random
import traceback
import shlex

from mumble import packets
from mumble import protobuf
from mumble.bot import MumbleBot

from chatterbotapi import ChatterBotFactory, ChatterBotType
from OpenSSL import SSL
from twisted.internet import reactor
from twisted.internet.ssl import ClientContextFactory
from twisted.internet.protocol import Factory


class MumbleResponseError(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return str(self.value)


class CommandFailedError(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return str(self.value)


class ArgumentsError(Exception):
	pass


class Hambone(MumbleBot):
	command_matcher = re.compile("^/(.*)")

	def __init__(self, *args, **kwargs):
		MumbleBot.__init__(self)
		self.setUsername("Hambone")
		self.toggleDeafened()
		self.setComment("I am merely a bot.")

		handlers = {
			packets.SERVERSYNC: self.initState,
			packets.TEXTMESSAGE: self.parseMessage
		}

		for ptype in handlers.keys():
			self.addHandler(ptype, handlers[ptype])

		self.user['data']['cbot'] = ChatterBotFactory().create(ChatterBotType.CLEVERBOT).create_session()
		self.user['data']['quotes'] = [
			"'give her the dick' -descartes",
			"'I need a tap and die and some WD-40.' -Hank Hill",
			"'The bitch went flying!' -Ben",
			"'It's all nice on ice.' -Ur mum",
			"'Do I look I know what a jaypeg is?' -Hank Hill"
		]

	def initState(self, data):
		self.syncState()

	def sendMessageToChannel(self, channel, msg):
		# print("Sending message to channel %i:\n\t%s." % (channel, msg))
		msg_packet = protobuf.TextMessage()
		msg_packet.actor = self.session
		msg_packet.channel_id.append(channel)
		msg_packet.message = str(msg)
		self.writeProtobuf(11, msg_packet)

	def sendMessageToUser(self, user, msg):
		# print("Sending message to user %i:\n\t%s." % (user, msg))
		msg_packet = protobuf.TextMessage()
		msg_packet.actor = self.session
		msg_packet.session.append(user)
		msg_packet.message = str(msg)
		self.writeProtobuf(11, msg_packet)

	def sendToProper(self, msg_packet, msg):
		if (msg_packet.channel_id):
			self.sendMessageToChannel(msg_packet.channel_id[0], msg)
		else:
			self.sendMessageToUser(msg_packet.actor, msg)

	def parseMessage(self, data):
		msg_packet = protobuf.TextMessage()
		msg_packet.ParseFromString(data)
		user = msg_packet.actor
		result = self.command_matcher.match(msg_packet.message)

		try:
			if result:
				user = self.users[msg_packet.actor]
				# if (user.name != "Czaalts"):
				# 	packet = mumble_proto.UserRemove()
				# 	packet.session = user.session
				# 	packet.actor = self.session
				# 	packet.reason = "Fuck off."

				# 	self.writeProtobuf(8, packet)
				# 	return
				args = shlex.split(result.group(1).replace("&quot;", "\""))
				command = args.pop(0).decode("UTF-8").lower()

				try:
					self.commands[command](self, msg_packet, user, args)
				except KeyError:
					raise CommandFailedError("Invalid command: '%s', use /commands to list available commands" % command)
				print("Ran command: '%s'." % msg_packet.message)
			elif re.match("^#", msg_packet.message):
				# msg = msg_packet.message[len(self.users[self.session].name + ", "):].encode("ascii")
				msg = msg_packet.message[1:].encode("ascii")
				task = reactor.callLater(3, self.sendToProper, self, msg_packet, "I'm thinking...")
				self.sendToProper(msg_packet, self.user['data']['cbot'].think(msg))
				task.cancel()
		except (ArgumentsError, CommandFailedError) as e:
			self.sendToProper(msg_packet, "Failed to run command due to: %s." % e)
		except:
			self.sendToProper(msg_packet, "Failed to run command '%s' with:<br/><blockquote>%s</blockquote>" % (msg_packet.message, traceback.format_exc().replace("\n", "<br/>")))

	def greetMe(self, msg_packet, user, args):
		dstr = "Hello " + user['name'] + " your id is " + str(user['user_id']) + ", the current channel you are in is " + str(user['channel_id']) + "."
		self.sendToProper(msg_packet, dstr)

	def comeToMe(self, msg_packet, user, args):
		self.setState(user['channel_id'], None, None, None)

	def followUser(self, data):
		state_packet = protobuf.UserState()
		state_packet.ParseFromString(data)

		if state_packet.session == self.user['data']['following']:
			self.setState(self.users[state_packet.session]['channel_id'], None, None, None)

	def followMe(self, msg_packet, user, args):
		if 'follow' in self.user['data']:
			self.sendToProper(msg_packet, "I am already following a user.")
			return
		self.user['data']['following'] = user['session']
		self.user['data']['follow'] = self.addHandler(9, self.followUser)

		self.setState(self.users[user['session']]['channel_id'], None, None, None)
		self.sendToProper(msg_packet, "I will now attempt to follow " + user['name'])

	def noFollow(self, msg_packet, user, args):
		self.removeHandler(9, self.user['data']['follow'])
		del self.user['data']['following']
		del self.user['data']['follow']

		self.sendToProper(msg_packet, "I will now stop following.")

	def roll(self, msg_packet, user, args):
		random.seed()
		n = 1
		m = 6

		if len(args) == 1:
			m = int(args[0])
		elif len(args) == 2:
			n = int(args[0])
			m = int(args[1])
		elif len(args) != 0:
			raise ArgumentsError("Invalid number of arguments %i" % len(args))

		if n > m:
			n, m = m, n
		elif n == m:
			if len(args) == 1 and n == 1 and m == 1:
				n = 0
			else:
				raise CommandFailedError("Cannot roll when minimum equals maximum")

		if n == 1:
			self.sendToProper(msg_packet, "%s rolled a d%i and got %i." % (user['name'], m, random.randrange(n, m)))
		else:
			self.sendToProper(msg_packet, "%s rolled between %i and %i and got %i." % (user['name'], n, m, random.randrange(n, m)))

	def pick(self, msg_packet, user, args):
		if (len(args) <= 1):
			raise ArgumentsError("Invalid number of arguments %i" % len(args))
		random.seed()
		self.sendToProper(msg_packet, "Hmmm, I pick '" + random.choice(args) + "'.")

	def dance(self):
		if not self.dancing:
			return
		for ele in self.users:
			if self.users[ele]['session'] == self.session:
				continue

			random.seed()
			channel_id = random.randrange(len(self.channels))
			packet = protobuf.UserState()
			packet.channel_id = channel_id
			packet.session = self.users[ele]['session']
			packet.actor = self.session
			self.writeProtobuf(9, packet)
		reactor.callLater(1, self.Dance)

	def danceParty(self, msg_packet, user, args):
		self.sendToProper(msg_packet, "Initializing dance party!")
		self.dancing = True
		self.dance()

	def stopDance(self, msg_packet, user, args):
		self.dancing = False

	def echo(self, msg_packet, user, args):
		self.sendToProper(msg_packet, " ".join(args))

	def quote(self, msg_packet, user, args):
		self.sendMessageToChannel(self.users[self.session]['channel_id'], "Quote of the now: " + random.choice(self.user['data']['quotes']))

	def away(self, msg_packet, user, args):
		if 'away' not in user['data']:
			user['data']['away'] = False

		user['data']['away'] = not user['data']['away']

		if user['data']['away'] is True:
			self.sendMessageToChannel(user['channel_id'], "%s has went away." % user['name'])
		elif user['data']['away'] is False:
			self.sendMessageToChannel(user['channel_id'], "%s has come back from being away." % user['name'])
		else:
			raise Exception("Something didn't work in away.")

	def isaway(self, msg_packet, user, args):
		if len(args) != 1:
			raise ArgumentsError("Invalid number of arguments: %i" % len(args))
		session = self.findUser(args[0])
		if session == -1:
			raise CommandFailedError("Unable to find user by the name of '%s'" % args[0])
		user = self.users[session]
		if 'away' not in user['data']:
			user['data']['away'] = False
		self.sendToProper(msg_packet, "%s away state is: %s." % (user['name'], user['data']['away']))

	def commands(self, msg_packet, user, args):
		self.sendToProper(msg_packet, "Commands are:\n%s" % self.commands.keys())

	def dump(self, msg_packet, user, args):
		if len(args) != 1:
			raise ArgumentsError("Invalid number of arguments: %i" % len(args))
		if args[0].find("users") == 0:
			for (session, user) in list(self.users.items()):
				print("%i: %s(%i)" % (session, user, len(user['comment'])))
		elif args[0].find("channels") == 0:
			for (i, channel) in list(self.channels.items()):
				print("%i: %s" % (i, channel))
		else:
			raise ArgumentsError("Not a valid subcommand")

	commands = {
		"greetme": greetMe,
		"cometome": comeToMe,
		"followme": followMe,
		"nofollow": noFollow,
		"roll": roll,
		"pick": pick,
		# "danceparty": danceParty,
		# "plsnomore": stopDance,
		"echo": echo,
		"quote": quote,
		"away": away,
		"isaway": isaway,
		"commands": commands,
		"dump": dump
	}


class HamboneFactory(Factory):
	def __init__(self):
		pass

	def buildProtocol(self, addr):
		return Hambone()

	def startedConnecting(self, connector):
		pass

	def clientConnectionFailed(self, connector, reason):
		pass

	def clientConnectionLost(self, connector, reason):
		print("Failed connection reconnecting.")
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

reactor.connectSSL("shio.moe", 64738, HamboneFactory(), CtxFactory())
reactor.run()
