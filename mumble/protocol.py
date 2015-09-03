import struct
import re
import json
import time
import traceback

from twisted.internet.protocol import Protocol, DatagramProtocol


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
	def __init__(self):
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
		print("added handler for type: %i" % ptype)
		self.handlers[ptype].append(f)
		return len(self.handlers[ptype]) - 1

	def removeHandler(self, ptype, index):
		del self.handlers[ptype][index]

	def writeProtobuf(self, ptype, proto):
		print("Sending packet of id: %s." % ptype)
		header = struct.pack("!h", ptype) + struct.pack("!i", proto.ByteSize())
		pstr = header + proto.SerializeToString()
		self.transport.write(pstr)

	def interpretType(self, data):
		self.packet_type = struct.unpack("!h", data[0:2])[0]
		self.packet_len = struct.unpack("!i", data[2:6])[0]
		self.packet = data[6:6 + self.packet_len]

		self.packets_received += 1

		print("Received packet of id: %s and length of: %i got packet size of: %i" % (self.packet_type, self.packet_len, len(self.packet)))
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


class MumbleUDP(DatagramProtocol):
	# ping_header = bytearray([0x0, 0x0, 0x01, 0x0,  0x0, 0x0, 0x0, 0x0])
	ping_header = int('00100000', 2)
	ip = None

	def __init__(self, ip):
		print "got ip of:", ip
		self.ip = ip

	def prin(self, obj):
		print ''.join(x.encode('hex') for x in obj)

	def sendPing(self):
		print "sending udp ping"
		timestamp = int(round(time.time(), 0))
		varint = varint_pb2.VarInt()
		varint.int = timestamp
		timestamp_var = varint.SerializeToString()[1:]
		self.prin(timestamp_var)
		packet = str(self.ping_header) + str(timestamp_var)
		print ''.join(x.encode('hex') for x in packet)
		self.transport.write(packet)

	def startProtocol(self):
		print "connecting to udp"
		self.transport.connect(self.ip, 64738)
		self.sendPing()

	def datagramReceived(self, data, (host, port)):
		print "received %r from %s:%d" % (data, host, port)
		# self.transport.write(data, (host, port))

# reactor.resolve("shio.moe").addCallback(lambda ip: reactor.listenUDP(0, UDP(ip)))
