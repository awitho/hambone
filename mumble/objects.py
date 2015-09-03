class MumbleUser(dict):
	def __init__(self, *args, **kwargs):
		super(dict, self).__init__(*args, **kwargs)
		self['session'] = 0
		self['name'] = ""
		self['user_id'] = 0
		self['channel_id'] = 0
		self['muted'] = False
		self['deafened'] = False
		self['suppressed'] = False
		self['self_mute'] = False
		self['self_deaf'] = False
		self['priority_speaker'] = False
		self['comment'] = ""
		self['data'] = {}


class MumbleChannel(dict):
	def __init__(self, *args, **kwargs):
		super(dict, self).__init__(*args, **kwargs)
		self['channel_id'] = 0
		self['parent'] = 0
		self['name'] = ""
		self['description'] = ""
		self['temporary'] = False
		self['position'] = 0
		self['data'] = {}
