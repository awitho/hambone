import re
import random
import traceback
import shlex

import config
from mumble import packets, protobuf, html
from mumble.protocol import MumbleUDP
from mumble.bot import MumbleBot

from chatterbotapi import ChatterBotFactory, ChatterBotType

from twisted.internet import reactor


class MumbleResponseError(Exception):
	pass


class CommandFailedError(Exception):
	pass


class CommandSyntaxError(Exception):
	pass


class PermissionsError(Exception):
	pass


class Hambone(MumbleBot):
	command_matcher = re.compile("^/(.*)")

	def __init__(self, *args, **kwargs):
		MumbleBot.__init__(self, "Hambone", *args, **kwargs)

		handlers = {
			packets.SERVERSYNC: self.initState,
			packets.TEXTMESSAGE: self.parseMessage,
		}

		for ptype in handlers.keys():
			self.addHandler(ptype, handlers[ptype])

	def userJoined(self, user):
		self.logger.info("%s joined." % user['name'])

	def userLeft(self, user):
		self.logger.info("%s left." % user['name'])

	def initState(self, data):
		self.user['data']['cbot'] = ChatterBotFactory().create(ChatterBotType.CLEVERBOT).create_session()
		self.user['data']['quotes'] = [
			"'give her the dick' -descartes",
			"'I need a tap and die and some WD-40.' -Hank Hill",
			"'The bitch went flying!' -Ben",
			"'It's all nice on ice.' -Ur mum",
			"'Do I look I know what a jaypeg is?' -Hank Hill"
		]

		if self.user['comment'] == "":
			self.setComment("I am merely a bot.")

		self.toggleDeafened()

	def firstHeartbeat(self, data):
		reactor.resolve("shio.moe").addCallback(lambda ip: reactor.listenUDP(57891, MumbleUDP(ip, self.key, self.client_nonce, self.server_nonce)))

	def sendToProper(self, msg_packet, msg):
		if (msg_packet.channel_id):
			self.sendMessageToChannel(msg_packet.channel_id[0], msg)
		else:
			self.sendMessageToUser(msg_packet.actor, msg)

	def parseMessage(self, data):
		msg_packet = protobuf.TextMessage()
		msg_packet.ParseFromString(data)
		user = msg_packet.actor
		result = self.command_matcher.match(html.unescape(msg_packet.message))

		try:
			if result:
				user = self.users[msg_packet.actor]
				args = shlex.split(result.group(1))
				command = args.pop(0).decode("UTF-8").lower()

				if command not in self.commands:
					raise CommandFailedError("Invalid command: '%s', use /commands to list available commands" % command)

				try:
					if re.match(config.admins[user['name']], command) is None:
						raise PermissionsError("Insufficient permissions")
				except KeyError:
					if '@' not in config.admins or re.match(config.admins['@'], command) is None:
						raise PermissionsError("Insufficient permissions")

				self.commands[command](self, msg_packet, user, args)
				self.logger.info("%s ran command: '%s'." % (user['name'], msg_packet.message))
			elif re.match("^#", msg_packet.message):
				msg = msg_packet.message[1:].encode("ascii")
				task = reactor.callLater(3, self.sendToProper, self, msg_packet, "I'm thinking...")
				self.sendToProper(msg_packet, self.user['data']['cbot'].think(msg))
				task.cancel()
		except (CommandFailedError, PermissionsError) as e:
			self.logger.error("Failed to run command due to: %s." % e)
		except CommandSyntaxError as e:
			self.logger.error("Invalid command syntax try: %s" % e)
		except:
			self.logger.error("Failed to run command '%s' with:\n<blockquote>%s</blockquote>" % (msg_packet.message, traceback.format_exc()))

	def greetMe(self, msg_packet, user, args):
		self.sendToProper(msg_packet, "Hello %s your id is %i, the current channel you are in is %i." % (user['name'], user['user_id'], user['channel_id']))

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
		self.sendToProper(msg_packet, "I will now attempt to follow %s." % user['name'])

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
			raise CommandSyntaxError("/roll [minimum] [maximum]")

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
			raise CommandSyntaxError("/pick <object> ...")
		random.seed()
		self.sendToProper(msg_packet, "Hmmm, I pick '%s'." % random.choice(args))

	def dance(self):
		if not self.user['data']['dancing']:
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
		if len(args) == 1:
			if args[0] == "stop":
				if 'dancing' not in self.user['data'] or not self.user['data']['dancing']:
					self.sendToProper(msg_packet, "No dancy party has been started!")
					return
				self.user['data']['dancing'] = False
			elif args[0] == "start":
				self.sendToProper(msg_packet, "Initializing dance party!")
				self.user['data']['dancing'] = True
				self.dance()
		else:
			raise CommandSyntaxError("/dance <start|stop>")

	def echo(self, msg_packet, user, args):
		self.sendToProper(msg_packet, " ".join(args))

	def quote(self, msg_packet, user, args):
		self.sendMessageToChannel(self.users[self.session]['channel_id'], "Quote of the now: '%s'." % random.choice(self.user['data']['quotes']))

	def announceAway(self):
		aways = []
		for (session, user) in list(self.users.items()):
			if 'away' in user['data'] and user['data']['away']:
				aways.append(user['name'])
		if len(aways) > 0:
			self.sendMessageToChannel(self.user['channel_id'], "%s are currently away." % (aways))
		reactor.callLater(30, self.announceAway)

	def away(self, msg_packet, user, args):
		if 'away' not in user['data']:
			user['data']['away'] = False

		user['data']['away'] = not user['data']['away']

		if user['data']['away'] is True:
			self.sendMessageToChannel(user['channel_id'], "%s has went away." % user['name'])
		elif user['data']['away'] is False:
			self.sendMessageToChannel(user['channel_id'], "%s has come back from being away." % user['name'])
		else:
			raise CommandFailedError("Logic has failed us all.")

	def isaway(self, msg_packet, user, args):
		if len(args) != 1:
			raise CommandSyntaxError("/isaway <user>")
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
			raise CommandSyntaxError("/dump <users|channels>")
		if args[0].find("users") == 0:
			for (session, user) in list(self.users.items()):
				self.logger.debug("%i: %s" % (session, user))
		elif args[0].find("channels") == 0:
			for (i, channel) in list(self.channels.items()):
				self.logger.debug("%i: %s" % (i, channel))
		else:
			raise CommandSyntaxError("Not a valid subcommand: %s" % args[0])

	def stop(self, msg_packet, user, args):
		self.transport.abortConnection()

	def restart(self, msg_packet, user, args):
		self.transport.loseConnection()

	commands = {
		"greetme": greetMe,
		"cometome": comeToMe,
		"followme": followMe,
		"nofollow": noFollow,
		"roll": roll,
		"pick": pick,
		"dance": danceParty,
		"echo": echo,
		"quote": quote,
		"away": away,
		"isaway": isaway,
		"commands": commands,
		"dump": dump,
		"stop": stop,
		"restart": restart,
	}
