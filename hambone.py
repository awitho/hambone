#!/usr/bin/env python
# -*- coding: utf-8 -*-

# stdlib
import copy
import re
import random
import traceback
import shlex
import wave

# stdlib from imports
from io import BytesIO
from enum import Enum

import pyaudio

# global libraries from imports
from bs4 import BeautifulSoup
from twisted.internet import reactor

# local libraries from imports
from volvo.scripts.games_diff import diff_games
from volvo.api import SteamAPI, ResponseException
from volvo.steamid import SteamID
from lib.chatterbotapi import ChatterBotFactory, ChatterBotType, ChatterBotException

# personal libraries
import config

# personal libraries from imports
from mumble import packets, protobuf, html, constants
from mumble.protocol import MumbleUDP, UDPMessageType
from mumble.bot import MumbleBot
from mumble.lib import varint, varint2
from mumble.lib.opus.decoder import Decoder as OpusDecoder
from mumble.lib.opus.encoder import Encoder as OpusEncoder


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


def listify(array, separator=", ", end_separator=" & "):
	last = array.pop()
	return "%s%s%s" % (separator.join(array), end_separator, last)


class register():
	_command = True

	def __init__(self, f):
		self.f = f

	def __call__(self, *args, **kwargs):
		return self.f(*args, **kwargs)


def interface_send(target, message):
	pass


class PermissionGroup(object):
	@staticmethod
	def hasCommand(data, command):
		if 'superuser' in data and data['superuser']:
			return True
		if command in data['commands']:
			return True
		elif 'parent' in data:
			return PermissionGroup.hasCommand(data['parent'], command)
		else:
			return False


class Command(object):
	def __init__(self, *args, **kwargs):
		super(Command, self).__init__(*args, **kwargs)
		self.name = None
		self.args = None
		self.type = None
		self.user = None
		self.message = None


class CommandType(Enum):
	TARGET_ADAPTIVE = 1
	TARGET_CHANNEL = 2
	TARGET_PRIVATE = 3
	TARGET_CBOT = 4

p = pyaudio.PyAudio()


class Hambone(MumbleBot):
	commands = {}
	command_delimiters = {"/": CommandType.TARGET_ADAPTIVE, "!": CommandType.TARGET_CHANNEL, "%": CommandType.TARGET_PRIVATE}

	def __init__(self, name="Hambone", *args, **kwargs):
		MumbleBot.__init__(self, name=name, *args, **kwargs)

		handlers = {
			packets.SERVERSYNC: self.initState,
			packets.PERMISSIONDENIED: self.permissionDenied,
			packets.TEXTMESSAGE: self.parseMessage,
		}

		if config.audio:
			self.addHandler(packets.UDPTUNNEL, self.udpTunnel)

		for ptype in handlers.keys():
			self.addHandler(ptype, handlers[ptype])

		self.opus_decoder = OpusDecoder(constants.SAMPLE_RATE, 2)
		self.opus_encoder = OpusEncoder(constants.SAMPLE_RATE, 1, "voip")
		self.opus_encoder.vbr = False
		with wave.open("clap.wav", "rb") as f:
			self.clap_pcm = f.readframes(f.getnframes())
		print(len(self.clap_pcm))
		self.clap_pcm = self.opus_encoder.encode_float(self.clap_pcm, constants.FRAME_SIZE)
		print(len(self.clap_pcm))

		self.audio_output = p.open(format=pyaudio.paFloat32, channels=2, rate=constants.SAMPLE_RATE, output=True)

		self._registerCommands()
		self.setupGroups(config)

	def udpTunnel(self, data):
		total_length = len(data)
		data = BytesIO(data)
		header = data.read(1)
		type = UDPMessageType.decode(header[0])
		target = header[0] & 0b00011111
		if type == UDPMessageType.Ping:
			# print("Encountered ping, done.")
			return
		session = varint2.decode_stream(data)
		if type == UDPMessageType.VoiceOpus:
			sequence = varint2.decode_stream(data)
		else:
			sequence = varint.decode_stream(data)
		# print(type, target, session, sequence)
		# print("Read {} bytes from header.".format(data.tell()))
		frame = 0
		while True:
			header = data.read(1)
			if len(header) != 1:
				# print("Couldn't read audio header.")
				break

			terminator = ((header[0] >> 7) & 0b00000001) == 1
			length = (header[0]) & 0b01111111
			frame += 1

			# print("Audio frame {} length: {}".format(frame, length))

			self.audio_output.write(self.opus_decoder.decode_float(data.read(length), constants.FRAME_SIZE))
			if terminator or data.tell() == total_length:
				# print("Terminated.")
				break
		# if data.tell() != total_length:
			# print("Trailing data?")
		# print()

	def _registerCommands(self):
		for f in dir(self):
			attr = getattr(self, f)
			if getattr(self, f) is not None and hasattr(attr, "_command"):
				self.registerCommand(f, getattr(self, f))

	def registerCommand(self, command, f):
		self.commands[command] = f

	def setupGroups(self, config):
		self.groups = {}
		self.default_group = None
		# parent groups to each other, circular references is going to murder this
		for (name, group) in copy.deepcopy(config.groups).items():
			if name in self.groups:
				return
			if 'parent' in group:
				if group['parent'] in config.groups:
					group['parent'] = config.groups[group['parent']]
				else:
					self.logger.warning("Could not find parent %s for group %s." % (group['parent'], name))

			if 'default' in group and group['default']:
				self.default_group = name

			self.groups[name] = group

	def userJoined(self, user):
		if user['name'] in config.users:
			self.users[user['session']]['data']['group'] = config.users[user['name']]
		else:
			self.users[user['session']]['data']['group'] = self.default_group

		if self.session is not None:
			greeting = config.greeting
			if not isinstance(greeting, list):
				greeting = [greeting]
			for line in greeting:
				self.sendMessageToUser(user['session'], line)
		self.logger.info("%s:%d joined." % (user['name'], user['session']))

	def userLeft(self, user):
		self.logger.info("%s:%d left." % (user['name'], user['session']))

	def permissionDenied(self, data):
		permission_packet = protobuf.PermissionDenied()
		permission_packet.ParseFromString(data)
		self.logger.warning("Permission denied: %s (%s)" % (permission_packet.reason, protobuf.PermissionDenied.DenyType.Name(permission_packet.type)))

	def initState(self, data):
		# self.toggleDeafened()

		if self.user['comment'] == "":
			self.setComment("I am merely a bot.")

	def firstHeartbeat(self, data):
		if config.udp:
			host = self.transport.getPeer()
			reactor.listenUDP(host.port, MumbleUDP(host.host, self.key, self.client_nonce, self.server_nonce))

	def sendToProper(self, msg_packet, msg):
		if (msg_packet.channel_id):
			self.sendMessageToChannel(msg_packet.channel_id[0], msg)
		else:
			self.sendMessageToUser(msg_packet.actor, msg)

	def hasPermission(self, user, command):
		return PermissionGroup.hasCommand(self.groups[user['data']['group']], command)

	def parseMessage(self, data):
		msg_packet = protobuf.TextMessage()
		msg_packet.ParseFromString(data)

		command = Command()
		command.message = BeautifulSoup(msg_packet.message[1:], "lxml").get_text()
		try:
			command.type = Hambone.command_delimiters[msg_packet.message[0]]
		except KeyError:
			return

		try:
			command.sender = self.users[msg_packet.actor]
			command.args = shlex_split(command.message)
			command.name = command.args.pop(0).lower()

			if command.name not in self.commands:
				raise CommandFailedError("Invalid command: '%s', use /help to list available commands" % command.name)

			if not self.hasPermission(command.sender, command.name):
				raise PermissionsError("Insufficient permissions")

			result = self.commands[command.name](self, msg_packet, command)
			if result:
				if not isinstance(result, list):
					result = [result]

				send_method = interface_send
				target = None
				if command.type == CommandType.TARGET_ADAPTIVE:
						send_method = self.sendToProper
						target = msg_packet
				elif command.type == CommandType.TARGET_CHANNEL:
						send_method = self.sendMessageToChannel
						target = self.user['channel_id']
				elif command.type == CommandType.TARGET_PRIVATE:
						target = msg_packet.actor
						send_method = self.sendMessageToUser
				buff = ""
				suffix = "<br/>"
				if len(result) != 1:
					for output in result:
						if len(buff) + len(output) + len(suffix) >= self.max_msg_len:
							send_method(target, buff)
							buff = ""
						else:
							if isinstance(output, bytes):
								output = output.decode('utf-8')
							buff += (output + suffix)
					if len(buff) > 0:
						send_method(target, buff)
				else:
					send_method(target, result[0])

			self.logger.info("%s ran command: '%s'." % (command.sender['name'], msg_packet.message))
		except (CommandFailedError, PermissionsError) as e:
			self.logger.error("Failed to run command '%s' due to: %s." % (command.name, e))
		except CommandSyntaxError as e:
			self.logger.error("Invalid command syntax try: %s" % e)
		except:
			self.logger.error("Failed to run command '%s' with:\n%s" % (msg_packet.message, traceback.format_exc()))

	@register
	def clap(self, msg_packet, command):
		pass

	@register
	def greet(self, msg_packet, command):
		channel = self.channels[command.sender['channel_id']]
		return "Hello %s [%i], the current channel you are in is %s [%i]." % (command.sender['name'], command.sender['user_id'], channel['name'], channel['channel_id'])

	@register
	def come(self, msg_packet, command):
		self.sendMessageToUser(command.sender['session'], "Right away, master.")
		self.setState(command.sender['channel_id'], None, None, None)

	def followUser(self, data):
		state_packet = protobuf.UserState()
		state_packet.ParseFromString(data)

		if state_packet.session == self.user['data']['following']:
			self.setState(self.users[state_packet.session]['channel_id'], None, None, None)

	@register
	def follow(self, msg_packet, command):
		if len(command.args) != 1:
			raise CommandSyntaxError("/follow <user|@stop|@me>")

		if command.args[0].find("@stop") == 0:
			if 'follow' not in self.user['data']:
				return "I am not following anyone."

			self.removeHandler(9, self.user['data']['follow'])
			del self.user['data']['following']
			del self.user['data']['follow']

			return "I will now stop following."
		else:
			if command.args[0].find("@me") == -1:
				user = self.users[self.findUser(command.args[0])]

			if user == -1:
				raise CommandFailedError("Could not find user '%s'" % command.args[0])

			if 'follow' in self.user['data']:
				return "I am already following a user."

			self.user['data']['following'] = user['session']
			self.user['data']['follow'] = self.addHandler(9, self.followUser)

			self.setState(self.users[user['session']]['channel_id'], None, None, None)
			return "I will now attempt to follow %s." % user['name']

	dice = re.compile("([1-9][0-9]*?)?d([1-9][0-9]*)")

	def rollDice(self, msg_packet, user, amount, dice):
		die = []
		for i in range(amount):
			die.append(random.randrange(1, dice + 1))

		return "%s rolled %id%i (%s) for a total of %i." % (user['name'], amount, dice, " + ".join([str(i) for i in die]), sum(die))

	@register
	def roll(self, msg_packet, command):
		random.seed()
		if len(command.args) < 2:
			amount = 1
			dice = 6

			if len(command.args) == 1:
				result = self.dice.match(command.args[0])
				if result:
					amount = int(result.group(1)) if result.group(1) else 1
					if amount > 1000:
						raise CommandFailedError("'%s' is too large a number for amount of dice" % amount)
					dice = int(result.group(2))
				else:
					try:
						dice = int(command.args[0])
					except ValueError:
						raise CommandFailedError("'%s' is not a valid integer for maximum" % command.args[0])

			return self.rollDice(msg_packet, command.sender, amount, dice)
		elif len(command.args) == 2:
			n = 1
			m = 6

			try:
				n = int(command.args[0])
			except ValueError:
				raise CommandFailedError("'%s' is not a valid integer for minimum" % command.args[0])

			try:
				m = int(command.args[1])
			except ValueError:
				raise CommandFailedError("'%s' is not a valid integer for maximum" % command.args[1])

			if n > m:
				n, m = m, n
			elif n == m:
				raise CommandFailedError("Cannot roll when minimum equals maximum")

			return "%s rolled between %i and %i and got %i." % (command.sender['name'], n, m, random.randrange(n, m + 1))
		else:
			raise CommandSyntaxError("/roll [minimum] [maximum] or /roll [amount]d[maximum] or /roll [maximum] or /roll")

	@register
	def pick(self, msg_packet, command):
		if (len(command.args) <= 1):
			raise CommandSyntaxError("/pick <object> ...")
		random.seed()
		return "Hmmm, I pick '%s'." % random.choice(command.args)

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
	def dance(self, msg_packet, command):
		if len(command.args) < 1:
			raise CommandSyntaxError("/dance <start|stop>")
		subcommand = command.args.pop(0).lower()
		if subcommand == "stop":
			if 'dancing' not in self.user['data'] or not self.user['data']['dancing']:
				return "No dancy party has been started!"
			self.user['data']['dancing'] = False
			return "Winding the party down... :("
		elif subcommand == "start":
			self.user['data']['dancing'] = True
			self.doDance()
			return "Initializing dance party!"

	echo_matcher = re.compile("^/\w* (.*)")

	@register
	def echo(self, msg_packet, command):
		return msg_packet.message[1 + len(command.name) + 1:]

	@register
	def quote(self, msg_packet, command):
		return "Quote of the now: %s" % random.choice(config.quotes)

	def announceAway(self):
		aways = []
		for (session, user) in list(self.users.items()):
			if 'away' in user['data'] and user['data']['away']:
				aways.append(user['name'])
		if len(aways) > 0:
			self.sendMessageToChannel(self.user['channel_id'], "%s are currently away." % (aways))
		reactor.callLater(30, self.announceAway)

	@register
	def away(self, msg_packet, command):
		if 'away' not in command.sender['data']:
			command.sender['data']['away'] = False

		command.sender['data']['away'] = not command.sender['data']['away']

		if command.sender['data']['away'] is True:
			self.sendMessageToChannel(command.sender['channel_id'], "%s has went away." % command.sender['name'])
		elif command.sender['data']['away'] is False:
			self.sendMessageToChannel(command.sender['channel_id'], "%s has come back from being away." % command.sender['name'])
		else:
			raise CommandFailedError("Logic has failed us all.")

	@register
	def isaway(self, msg_packet, command):
		if len(command.args) != 1:
			raise CommandSyntaxError("/isaway <user>")
		session = self.findUser(command.args[0])
		if session == -1:
			raise CommandFailedError("Unable to find user by the name of '%s'" % command.args[0])
		user = self.users[session]
		if 'away' not in user['data']:
			user['data']['away'] = False
		return "%s away state is: %s." % (user['name'], user['data']['away'])

	@register
	def help(self, msg_packet, command):
		commands = []
		for command_name in self.commands.keys():
			if self.hasPermission(command.sender, command_name):
				commands.append(command_name)
		return ["The command prefixes I have available are: %s" % ", ".join(["%s:%s" % (k, v.name) for (k, v) in self.command_delimiters.items()]), "The commands I have available are %s." % listify(commands)]

	@register
	def dump(self, msg_packet, command):
		if len(command.args) != 1:
			raise CommandSyntaxError("/dump <users|channels>")
		subcommand = command.args.pop()
		if subcommand == "users":
			for (session, user) in list(self.users.items()):
				self.logger.debug("%i: %s" % (session, user))
		elif subcommand == "channels":
			for (i, channel) in list(self.channels.items()):
				self.logger.debug("%i: %s" % (i, channel))
		else:
			raise CommandSyntaxError("Not a valid subcommand: %s" % subcommand)

	def chatterbotChatter(self, data):
		msg_packet = protobuf.TextMessage()
		msg_packet.ParseFromString(data)

		if msg_packet.message[0] in Hambone.command_delimiters:
			return

		try:
			self.sendToProper(msg_packet, html.escape(self.user['data']['cbot'].think(msg_packet.message)))
		except ChatterBotException:
			self.logger.error("Failed to communicate with chatterbot:\n%s" % traceback.format_exc())
		except ResponseException as r:
			self.logger.error("Unsuccesful response: %s" ("<br/>".join([str(x) for x in [r.status_code, r.url, r.headers, r.cookies]])))

	@register
	def chatterbot(self, msg_packet, command):
		if len(command.args) < 1:
			raise CommandSyntaxError("/chatterbot <type>")
		chatterbot_type = command.args.pop(0).upper()
		if chatterbot_type == "NONE":
			self.removeHandler(packets.TEXTMESSAGE, self.user['data']['cbotid'])
			del self.user['data']['cbotid']
			del self.user['data']['cbot']
			return "I have left chatterbot mode."

		if 'cbotid' in self.user['data']:
			return "I am already in chatterbot mode %s." % type(self.user['data']['cbot'])

		try:
			self.user['data']['cbot'] = ChatterBotFactory.create(ChatterBotType[chatterbot_type], *command.args)
		except KeyError:
			raise CommandFailedError("Invalid chatterbot '%s' type, available ones are: %s" % (chatterbot_type, listify([x.name for x in list(ChatterBotType)])))
		self.user['data']['cbotid'] = self.addHandler(packets.TEXTMESSAGE, self.chatterbotChatter)
		return "I have entered chatterbot mode %s." % chatterbot_type

	@register
	def define(self, msg_packet, command):
		if len(command.args) < 1:
			raise CommandSyntaxError("/define <word>")
		word = command.args.pop(0).lower()
		if word in config.definitions:
			return "%s: %s" % (word, config.definitions[word])
		return "I do not know how to define '%s'" % word

	@register
	def steam(self, msg_packet, command):
		if len(command.args) < 1:
			raise CommandSyntaxError("/steam <compare|id>")
		subcommand = command.args.pop(0).lower()
		if subcommand == "compare":
			if len(command.args) < 2:
				raise CommandSyntaxError("/steam compare <vanityurl|steamid|steamid64|steamid32> <vanityurl|steamid|steamid64|steamid32>...")

			steamids = []
			for id in command.args:
				steamid = SteamID.from_unknown(id)
				if steamid:
					steamids.append(steamid.to_steamid64())
				else:
					steamids.append(SteamAPI.resolve_vanity(id))

			games = diff_games(steamids)
			message = ["<a href='steam://run/%s'>%s</a>" % (game['appid'], game['name']) for game in sorted(games, key=lambda k: k['name'])]
			message.insert(0, "Here are the games that %s have in common." % (listify(command.args)))
			return message
		elif subcommand == "id":
			if len(command.args) != 1:
				raise CommandSyntaxError("/steam id <vanityurl|steamid|steamid64|steamid32>")
			steamid = SteamID.from_unknown(command.args[0])
			if not steamid:
				steamid = SteamID.from_steamid64(SteamAPI.resolve_vanity(command.args[0]))
			return ["<br/>Given input: %s" % command.args[0], "Converted SteamID: %s" % (steamid.to_steamid()), "Converted SteamID64: %d" % (steamid.to_steamid64()), "Converted SteamID32: %s" % (steamid.to_steamid32())]
		else:
			raise CommandSyntaxError("/steam <compare|id>")

	def spamThink(self, message):
		self.sendMessageToChannel(self.user['channel_id'], message)
		reactor.callLater(0.1, self.spamThink, message)

	@register
	def spam(self, msg_packet, command):
		if len(command.args) < 1:
			raise CommandSyntaxError("/spam <message>")
		self.spamThink(command.args[0])

	@register
	def shutdown(self, msg_packet, command):
		self.transport.abortConnection()

	@register
	def restart(self, msg_packet, command):
		self.transport.loseConnection()
