#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import random
import traceback
import shlex

from lib.chatterbotapi import ChatterBotFactory, ChatterBotType
from twisted.internet import reactor
from functools import wraps

import config
from mumble import packets, protobuf, html
from mumble.protocol import MumbleUDP
from mumble.bot import MumbleBot


class MumbleResponseError(Exception):
	pass


class CommandFailedError(Exception):
	pass


class CommandSyntaxError(Exception):
	pass


class PermissionsError(Exception):
	pass


def shlex_split(x):
	"""Helper function to split lines into segments."""
	# shlex.split raise exception if syntax error in sh syntax
	# for example if no closing " is found. This function keeps dropping
	# the last character of the line until shlex.split does not raise
	# exception. Adds end of the line to the result of shlex.split
	# example: %run "c:/python  -> ['%run','"c:/python']
	endofline = []
	while x != "":
		try:
			comps = shlex.split(x)
			if len(endofline) >= 1:
				comps.append("".join(endofline))
			return comps
		except ValueError:
			endofline = [x[-1:]] + endofline
			x = x[:-1]
	return ["".join(endofline)]


class register():
	_command = True

	def __init__(self, f):
		self.f = f

	def __call__(self, *args, **kwargs):
		return self.f(*args, **kwargs)


class Hambone(MumbleBot):
	commands = {}
	command_matcher = re.compile("^/(.*)")

	def __init__(self, *args, **kwargs):
		MumbleBot.__init__(self, "Hambone", *args, **kwargs)

		handlers = {
			packets.SERVERSYNC: self.initState,
			packets.TEXTMESSAGE: self.parseMessage,
		}

		for ptype in handlers.keys():
			self.addHandler(ptype, handlers[ptype])

		self._registerCommands()

	def _registerCommands(self):
		for f in dir(self):
			attr = getattr(self, f)
			if getattr(self, f) != None and hasattr(attr, "_command"):
				self.commands[f] = getattr(self, f)

	def userJoined(self, user):
		self.logger.info("%s joined." % user['name'])

	def userLeft(self, user):
		self.logger.info("%s left." % user['name'])

	def initState(self, data):
		self.user['data']['cbot'] = ChatterBotFactory().create(ChatterBotType.CLEVERBOT).create_session()

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

	def hasPermission(self, user, command):
		try:
			if re.match(config.admins[user], command) is None:
				return False
		except KeyError:
			if '@' not in config.admins or re.match(config.admins['@'], command) is None:
				return False
		return True

	def parseMessage(self, data):
		msg_packet = protobuf.TextMessage()
		msg_packet.ParseFromString(data)
		user = msg_packet.actor
		result = self.command_matcher.match(html.unescape(msg_packet.message))

		try:
			if result:
				user = self.users[msg_packet.actor]
				args = shlex_split(result.group(1))
				command = args.pop(0).decode("UTF-8").lower()

				if command not in self.commands:
					raise CommandFailedError("Invalid command: '%s', use /help to list available commands" % command)

				if not self.hasPermission(user['name'], command):
					raise PermissionsError("Insufficient permissions")

				self.commands[command](self, msg_packet, user, args)
				self.logger.info("%s ran command: '%s'." % (user['name'], msg_packet.message))
			elif re.match("^#", msg_packet.message):
				msg = msg_packet.message[1:].encode("ascii")
				task = reactor.callLater(3, self.sendToProper, self, msg_packet, "I'm thinking...")
				self.sendToProper(msg_packet, self.user['data']['cbot'].think(msg))
				task.cancel()
		except (CommandFailedError, PermissionsError) as e:
			self.logger.error("Failed to run command '%s' due to: %s." % (command, e))
		except CommandSyntaxError as e:
			self.logger.error("Invalid command syntax try: %s" % e)
		except:
			self.logger.error("Failed to run command '%s' with:\n%s" % (msg_packet.message, traceback.format_exc()))

	@register
	def greet(self, msg_packet, user, args):
		channel = self.channels[user['channel_id']]
		self.sendToProper(msg_packet, "Hello %s [%i], the current channel you are in is %s [%i]." % (user['name'], user['user_id'], channel['name'], channel['channel_id']))

	@register
	def come(self, msg_packet, user, args):
		self.setState(user['channel_id'], None, None, None)

	def followUser(self, data):
		state_packet = protobuf.UserState()
		state_packet.ParseFromString(data)

		if state_packet.session == self.user['data']['following']:
			self.setState(self.users[state_packet.session]['channel_id'], None, None, None)

	@register
	def follow(self, msg_packet, user, args):
		if len(args) != 1:
			raise CommandSyntaxError("/follow <user|@stop|@me>")

		if args[0].find("@stop") == 0:
			if 'follow' not in self.user['data']:
				self.sendToProper(msg_packet, "I am not following anyone.")
				return

			self.removeHandler(9, self.user['data']['follow'])
			del self.user['data']['following']
			del self.user['data']['follow']

			self.sendToProper(msg_packet, "I will now stop following.")
		else:
			if args[0].find("@me") == -1:
				user = self.users[self.findUser(args[0])]

			if user == -1:
				raise CommandFailedError("Could not find user '%s'" % args[0])

			if 'follow' in self.user['data']:
				self.sendToProper(msg_packet, "I am already following a user.")
				return

			self.user['data']['following'] = user['session']
			self.user['data']['follow'] = self.addHandler(9, self.followUser)

			self.setState(self.users[user['session']]['channel_id'], None, None, None)
			self.sendToProper(msg_packet, "I will now attempt to follow %s." % user['name'])

	dice = re.compile("([1-9][0-9]*?)?d([1-9][0-9]*)")

	def rollDice(self, msg_packet, user, amount, dice):
		die = []
		for i in range(amount):
			die.append(random.randrange(1, dice + 1))

		self.sendToProper(msg_packet, "%s rolled %id%i %s for a total of %i." % (user['name'], amount, dice, die, sum(die)))

	@register
	def roll(self, msg_packet, user, args):
		random.seed()
		if len(args) < 2:
			amount = 1
			dice = 6

			if len(args) == 1:
				result = self.dice.match(args[0])
				if result:
					amount = int(result.group(1)) if result.group(1) else 1
					dice = int(result.group(2))
				else:
					try:
						dice = int(args[0])
					except ValueError:
						raise CommandFailedError("'%s' is not a valid integer for maximum" % args[0])

			self.rollDice(msg_packet, user, amount, dice)
		elif len(args) == 2:
			n = 0
			m = 0

			try:
				n = int(args[0])
			except ValueError:
				raise CommandFailedError("'%s' is not a valid integer for minimum" % args[0])

			try:
				m = int(args[1])
			except ValueError:
				raise CommandFailedError("'%s' is not a valid integer for maximum" % args[1])

			if n > m:
				n, m = m, n
			elif n == m:
				if len(args) == 1 and n == 1 and m == 1:
					n = 0
			else:
				raise CommandFailedError("Cannot roll when minimum equals maximum")

			self.sendToProper(msg_packet, "%s rolled between %i and %i and got %i." % (user['name'], n, m, random.randrange(n, m + 1)))
		else:
			raise CommandSyntaxError("/roll [minimum] [maximum] or /roll [amount]d[maximum] or /roll [maximum] or /roll")

	@register
	def pick(self, msg_packet, user, args):
		if (len(args) <= 1):
			raise CommandSyntaxError("/pick <object> ...")
		random.seed()
		self.sendToProper(msg_packet, "Hmmm, I pick '%s'." % random.choice(args))

	def doDance(self):
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
		reactor.callLater(1, self.doDance)

	@register
	def dance(self, msg_packet, user, args):
		if len(args) == 1:
			if args[0] == "stop":
				if 'dancing' not in self.user['data'] or not self.user['data']['dancing']:
					self.sendToProper(msg_packet, "No dancy party has been started!")
					return
				self.user['data']['dancing'] = False
			elif args[0] == "start":
				self.sendToProper(msg_packet, "Initializing dance party!")
				self.user['data']['dancing'] = True
				self.doDance()
		else:
			raise CommandSyntaxError("/dance <start|stop>")

	echo_matcher = re.compile("^/\w* (.*)")

	@register
	def echo(self, msg_packet, user, args):
		result = self.echo_matcher.match(html.unescape(msg_packet.message))
		self.sendToProper(msg_packet, html.escape(result.group(1)))

	@register
	def quote(self, msg_packet, user, args):
		self.sendMessageToChannel(self.users[self.session]['channel_id'], "Quote of the now: %s." % random.choice(config.quotes))

	def announceAway(self):
		aways = []
		for (session, user) in list(self.users.items()):
			if 'away' in user['data'] and user['data']['away']:
				aways.append(user['name'])
		if len(aways) > 0:
			self.sendMessageToChannel(self.user['channel_id'], "%s are currently away." % (aways))
		reactor.callLater(30, self.announceAway)

	@register
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

	@register
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

	@register
	def help(self, msg_packet, user, args):
		commands = []
		for command in self.commands.keys():
			if self.hasPermission(user['name'], command):
				commands.append(command)
		self.sendToProper(msg_packet, "Commands are:\n%s" % commands)

	@register
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

	@register
	def shutdown(self, msg_packet, user, args):
		self.transport.abortConnection()

	@register
	def restart(self, msg_packet, user, args):
		self.transport.loseConnection()
