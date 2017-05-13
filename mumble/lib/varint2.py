"""Varint encoder/decoder

varints are a common encoding for variable length integer data, used in
libraries such as sqlite, protobuf, v8, and more.

Here's a quick and dirty module to help avoid reimplementing the same thing
over and over again.
"""

# byte-oriented StringIO was moved to io.BytesIO in py3k
try:
	from io import BytesIO
except ImportError:
	from StringIO import StringIO as BytesIO

import sys

if sys.version > '3':
	def _byte(b):
		return bytes((b, ))
else:
	def _byte(b):
		return chr(b)


def next(stream):
	"""Read a byte from the file (as an integer)

	raises EOFError if the stream ends while reading bytes.
	"""
	c = stream.read(1)
	if c == '':
		raise EOFError("Unexpected EOF while reading bytes")
	return ord(c)


def encode(number):
	"""Pack `number` into varint bytes"""
	buf = b''
	while True:
		towrite = number & 0x7f
		number >>= 7
		if number:
			buf += _byte(towrite | 0x80)
		else:
			buf += _byte(towrite)
			break
	return buf


def decode_stream(stream):
	"""Read a varint from `stream`"""
	v = next(stream)

	if (v & 0x80) == 0x00:
		return (v & 0x7F)
	elif (v & 0xC0) == 0x80:
		return (v & 0x3F) << 8 | next(stream)
	elif (v & 0xF0) == 0xF0:
		shift = (v & 0xFC)
		if shift == 0xF0:
			return next(stream) << 24 | next(stream) << 16 | next(stream) << 8 | next(stream)
		elif shift == 0xF4:
			return next(stream) << 56 | next(stream) << 48 | next(stream) << 40 | next(stream) << 32 | next(stream) << 24 | next(stream) << 16 | next(stream) << 8 | next(stream)
		elif shift == 0xF8:
			return ~(decode_stream(stream))
		elif shift == 0xFC:
			return ~(v & 0x03)
		else:
			return 0
	elif (v & 0xF0) == 0xE0:
		return (v & 0x0F) << 24 | next(stream) << 16 | next(stream) << 8 | next(stream)
	elif (v & 0xE0) == 0xC0:
		return (v & 0x1F) << 16 | next(stream) << 8 | next(stream)
	return 0


def decode_bytes(buf):
	"""Read a varint from from `buf` bytes"""
	return decode_stream(BytesIO(buf))
