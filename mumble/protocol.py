import struct
import time
import traceback
import random
import logging
import binascii

from enum import Enum

from .lib import varint
from .lib.ocb.aes import AES
from .lib.ocb import OCB

from twisted.internet.protocol import Protocol, ConnectedDatagramProtocol


def encodeVersion(major, minor, patch):
	return (major << 16) | (minor << 8) | (patch & 0xFF)


def decodeVersion(version):
	return (version & ~0x0000FFFF) >> 16, (version & ~0xFFFF00FF) >> 8, (version & ~0xFFFFFF00)


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


class MumbleProtocol(Protocol):
	def __init__(self, *args, **kwargs):
		self.handlers = {}
		self.expecting = []

		self.packets_received = 0
		self.chunked_packet = False

	def connectionMade(self):
		pass

	def connectionLost(self, reason):
		pass

	def dataReceived(self, data):
		self.interpretType(data)

	def addHandler(self, ptype, f):
		if f is None:
			return
		if ptype not in self.handlers:
			self.handlers[ptype] = []
		# print("added handler for type: %i" % ptype)
		self.handlers[ptype].append(f)
		return len(self.handlers[ptype]) - 1

	def removeHandler(self, ptype, index):
		if index is None:
			return
		del self.handlers[ptype][index]

	def writeProtobuf(self, ptype, proto):
		# print("Sending packet of id: %s." % ptype)
		header = struct.pack("!h", ptype) + struct.pack("!i", proto.ByteSize())
		pstr = proto.SerializeToString()
		self.transport.write(header + pstr[:1024])
		if len(pstr) > 1024:
			# print("Packet is longer than 1024 (%s), chunking." % (len(pstr)))
			for i in range(1024, len(pstr) + 1, 1024):
				self.transport.write(pstr[i:i + 1024])

	def interpretType(self, data):
		if not self.chunked_packet:
			self.packet_type = struct.unpack("!h", data[0:2])[0]
			self.packet_len = struct.unpack("!i", data[2:6])[0]
			self.packet = data[6:6 + self.packet_len]
		else:
			self.packet = self.packet + data[0:self.packet_len - len(self.packet)]

		if len(self.packet) < self.packet_len:
			self.chunked_packet = True
			return
		else:
			self.chunked_packet = False

		self.packets_received += 1

		# print("Received packet of id: %s and length of: %i got packet size of: %i" % (self.packet_type, self.packet_len, len(self.packet)))
		if self.packet_type in self.handlers:
			for handler in self.handlers[self.packet_type]:
				try:
					handler(self.packet)
				except:
					print("Failed to run handler for packet %i exception:\n%s" % (self.packet_type, traceback.format_exc()))
		else:
			pass  # print "Received unknown packet of id:", self.packet_type, "and length of:", self.packet_len, "got packet size of:", len(self.packet)

		if (len(data) - (6 + self.packet_len) > 0):
			self.interpretType(data[6 + self.packet_len:])


class ConnectedOCBDatagramProtocol(ConnectedDatagramProtocol):
	def __init__(self, ip, key, client_nonce, server_nonce, *args, **kwargs):
		print(key, len(key))
		print(client_nonce, len(client_nonce))
		print(server_nonce, len(server_nonce))
		self.ip = ip
		self.key = bytearray(key)
		self.client_nonce = bytearray(client_nonce)
		self.server_nonce = bytearray(server_nonce)

		def hexlify(bytearray):
			return ''.join(["%02x" % x for x in bytearray])

		print("OCB-AES128 Key: %s, Client Nonce: %s, Server Nonce: %s" % (hexlify(self.key), hexlify(self.client_nonce), hexlify(self.server_nonce)))

		self.ocb = OCB(AES(128))
		self.ocb.setKey(self.key)
		self.ocb.setNonce(self.server_nonce)

	def write(self, data):
		"""
		4 byte header is:
		First byte of client nonce followed by first three bytes of tag
		"""
		(tag, ciphertext) = self.ocb.encrypt(bytearray(data), bytearray())
		data = self.server_nonce[0:1] + tag[0:3] + ciphertext
		print("Ciphertext len: {}, Headered data len: {}".format(len(ciphertext), len(data)))
		self.transport.write(data)

	def datagramReceived(self, data, addr):
		self.ocb.decrypt()


class UDPMessageType(Enum):
	VoiceCELTAlpha = 0
	Ping = 1
	VoiceSpeex = 2
	VoiceCELTBeta = 3
	VoiceOpus = 4

	def encode(self):
		return self.value << 5

	@classmethod
	def decode(self, data):
		return self((data >> 5) & 0x7)


class MumbleUDP(ConnectedOCBDatagramProtocol):
	"""
	There are two types of packets that get sent over UDP with mumble, encrypted
	"typed" packets and a unencrypted ping type that is separate from the "typed" ping.

	Encrypted packets have a 4 byte crypt header and a 1 byte header for mumble.
	"""
	format = logging.Formatter("%(asctime)-15s %(name)-3s | %(levelname)-6s: %(message)s")

	def __init__(self, *args, **kwargs):
		super(MumbleUDP, self).__init__(*args, **kwargs)

		self.logger = logging.getLogger("hambone-udp")
		if self.logger.handlers == []:
			self.logger.setLevel(logging.DEBUG)

			file = logging.handlers.RotatingFileHandler("hambone-udp.log", maxBytes=512 * 1024, backupCount=3)
			file.setFormatter(self.format)
			self.logger.addHandler(file)

			console = logging.StreamHandler()
			console.setFormatter(self.format)
			self.logger.addHandler(console)

	def setVarint(self, obj):
		print(obj)

	def bytearrayToBinaryString(self, array):
		s = ""
		for c in array:
			s = s + '{0:08b} '.format(c, 'b')
		return s

	def toBytearray(self, string):
		array = bytearray()
		for c in string:
			array.append(c)
		return array

	def reverseBytearray(self, array):
		r = bytearray()
		for c in array:
			r.append(int('{0:b}'.format(c)[::-1], 2))
		return r

	def sendPing(self):
		"""
		Example ping is 0cdb00650d6c3d9e
		"""
		self.write(struct.pack("!B", UDPMessageType.Ping.encode()) + b"\x00" * 3)

	def sendStatPing(self):
		data = binascii.unhexlify("0000000031319001b1050000")
		self.logger.debug("Sending ping \"{}\":{}...".format(data, len(data)))
		self.transport.write(data)

	def startProtocol(self):
		self.transport.connect(self.ip, 64738)
		self.logger.debug("Connected to %s" % self.ip)
		self.sendPing()

	def connectionFailed(self, failure):
		self.logger.debug("refused")

	def datagramReceived(self, data, addr):
		self.logger.debug("Received packet with contents: {}".format(data))
		(major, minor, patch, timestamp, users, max_users, bandwidth) = struct.unpack("!HBB8sIII", data)
		print(major, minor, patch, varint.decode_bytes(timestamp), users, max_users, bandwidth)
