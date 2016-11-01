from .protobuf import UserState, ChannelState


class Protobuf(dict):
	def from_protobuf(self, protobuf):
		for key in dir(protobuf):
			if key in self and protobuf.HasField(key):
				self[key] = getattr(protobuf, key)

	def to_protobuf(self):
		protobuf = self.buf_type()
		for key in dir(protobuf):
			if key in self:
				setattr(protobuf, key, self[key])
		return protobuf


class MumbleUser(Protobuf):
	buf_type = UserState

	def __init__(self, *args, **kwargs):
		super(dict, self).__init__(*args, **kwargs)
		self['session'] = 0
		self['name'] = ""
		self['user_id'] = 0
		self['channel_id'] = 0
		self['mute'] = False
		self['deaf'] = False
		self['suppress'] = False
		self['self_mute'] = False
		self['self_deaf'] = False
		self['priority_speaker'] = False
		self['comment'] = ""
		self['data'] = {}


class MumbleChannel(Protobuf):
	buf_type = ChannelState

	def __init__(self, *args, **kwargs):
		super(dict, self).__init__(*args, **kwargs)
		self['channel_id'] = 0
		self['parent'] = 0
		self['name'] = ""
		self['description'] = ""
		self['temporary'] = False
		self['position'] = 0
		self['data'] = {}
