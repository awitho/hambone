import varint
# coding=utf-8

packet = "F169C5DFA276AFC3"
# packet = "69C5DFA276AFC3"
# packet = "5463691C856B086F"
# packet = "5463691C856B086F"

byte = bytearray()
for c in packet.decode('hex'):
	byte.append(c)

for c in byte:
	print('{0:08b} '.format(c, 'b'))

(result, pos) = varint.decodeVarint(str(packet), 0)
print(result)
