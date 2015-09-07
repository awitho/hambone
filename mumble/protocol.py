import struct
import re
import json
import time
import traceback
import random
import logging

from ocb.aes import AES
from ocb import OCB

from twisted.internet.protocol import Protocol, ConnectedDatagramProtocol

from . import varint


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

	def connectionMade(self):
		pass

	def connectionLost(self, reason):
		pass

	def dataReceived(self, data):
		self.interpretType(data)

	def addHandler(self, ptype, f):
		if ptype not in self.handlers:
			self.handlers[ptype] = []
		# print("added handler for type: %i" % ptype)
		self.handlers[ptype].append(f)
		return len(self.handlers[ptype]) - 1

	def removeHandler(self, ptype, index):
		del self.handlers[ptype][index]

	def writeProtobuf(self, ptype, proto):
		# print("Sending packet of id: %s." % ptype)
		header = struct.pack("!h", ptype) + struct.pack("!i", proto.ByteSize())
		pstr = header + proto.SerializeToString()
		self.transport.write(pstr)

	def interpretType(self, data):
		self.packet_type = struct.unpack("!h", data[0:2])[0]
		self.packet_len = struct.unpack("!i", data[2:6])[0]
		self.packet = data[6:6 + self.packet_len]

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


class MumbleUDP(ConnectedDatagramProtocol):
	ping_header = 0b00100000
	empty = bytearray()
	format = logging.Formatter("%(asctime)-15s %(name)-3s | %(levelname)-6s: %(message)s")

	def __init__(self, ip, key, client_nonce, server_nonce):
		self.ip = ip
		self.key = bytearray(key)
		self.client_nonce = bytearray(client_nonce)
		self.server_nonce = bytearray(server_nonce)
		self.logger = logging.getLogger("hambone-udp")
		if self.logger.handlers == []:
			self.logger.setLevel(logging.DEBUG)

			file = logging.handlers.RotatingFileHandler("hambone-udp.log", maxBytes=512 * 1024, backupCount=3)
			file.setFormatter(self.format)
			self.logger.addHandler(file)

			console = logging.StreamHandler()
			console.setFormatter(self.format)
			self.logger.addHandler(console)

		self.logger.debug("OCB-AES128 Key: %s, Client Nonce: %s, Server Nonce: %s" % (str(self.key).encode('hex'), str(self.client_nonce).encode('hex'), str(self.server_nonce).encode('hex')))

		self.ocb = OCB(AES(128))
		self.ocb.setKey(self.key)

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
		# timestamp_int = int(round(time.time(), 0))
		timestamp_int = int(time.time())
		timestamp = bytearray()
		varint.encodeVarint(timestamp.append, timestamp_int)
		(result, pos) = varint.decodeVarint(str(timestamp), 0)
		self.logger.debug("Timestamp encoded and then decoded is: %i, %i" % (timestamp_int, result))

		packet = bytearray()
		packet.append(self.ping_header)
		timestamp = self.toBytearray(timestamp)
		packet.extend(timestamp)

		self.writePacket(packet)

	def writePacket(self, packet):
		self.logger.debug("Unencrypted packet: %s" % str(packet).encode('hex'))
		self.ocb.setNonce(self.client_nonce)
		header = bytearray(struct.pack('!BBBB', random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))
		(tag, cipher) = self.ocb.encrypt(packet, header)

		# self.ocb.setNonce(self.client_nonce)
		# (auth, plaintext) = self.ocb.decrypt(header, cipher, tag)
		# print("Decrypted packet (%s): %s" % (auth, str(plaintext).encode("hex")))

		packet = bytearray()
		packet.extend(header)
		packet.extend(cipher)
		self.logger.debug("Sending packet with contents: %s (%s)" % (self.bytearrayToBinaryString(packet), str(packet).encode('hex')))
		self.transport.write(packet)

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
