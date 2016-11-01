import struct
import time
import traceback
import random
import logging

from .lib import varint

from Crypto.Cipher import AES
from twisted.internet.protocol import Protocol, ConnectedDatagramProtocol


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
		self.key = bytes(key)
		self.client_nonce = bytes(client_nonce)
		self.server_nonce = bytes(server_nonce)

		self.ocb = AES.new(self.key, AES.MODE_OCB, nonce=self.client_nonce)

	def write(self, data):
		# self.ocb.setNonce(self.client_nonce)
		# (auth, plaintext) = self.ocb.decrypt(header, cipher, tag)
		# print("Decrypted packet (%s): %s" % (auth, str(plaintext).encode("hex")))
		# header = struct.pack('!BBBB', random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
		print("Writing: %s (%s)" % (data, len(data)))
		(ciphertext, mac) = self.ocb.encrypt_and_digest(data)
		self.transport.write(ciphertext)


def hexlify(bytearray):
	return ''.join(["%02x" % x for x in bytearray])


class MumbleUDP(ConnectedOCBDatagramProtocol):
	ping_header = bytes(0b00100000)
	empty = bytearray()
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

		self.logger.debug("OCB-AES128 Key: %s, Client Nonce: %s, Server Nonce: %s" % (hexlify(self.key), hexlify(self.client_nonce), hexlify(self.server_nonce)))

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
		self.write(self.ping_header + varint.encode(int(time.time())))

	def startProtocol(self):
		self.transport.connect(self.ip, 64738)
		self.logger.debug("Connected to %s" % self.ip)
		self.sendPing()

	def connectionFailed(self, failure):
		self.logger.debug("refused")

	def datagramReceived(self, data, addr):
		packet = bytearray()
		self.appendStringToBytearray(data, packet)
		self.logger.debug("Received packet with contents: %s (%s)" % (self.bytearrayToBinaryString(packet), data.encode('hex')))
