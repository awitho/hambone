import re
import sys
import hashlib
import uuid

from collections import OrderedDict
from enum import Enum
from urllib.parse import urlencode

import requests

from lxml import etree


"""
	chatterbotapi
	Copyright (C) 2011 pierredavidbelanger@gmail.com

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

#################################################
# API
#################################################


class GettableList(list):
	def __init__(self, *args, default=None, **kwargs):
		super(GettableList, self).__init__(*args, **kwargs)
		self.default = default

	def get(self, idx):
		try:
			return self[idx]
		except IndexError:
			return self.default


class ChatterBotException(Exception):
	pass


class ResponseException(ChatterBotException):
	pass


class ChatterBotType(Enum):
	CLEVERBOT = 1
	# JABBERWACKY = 2
	PANDORABOT = 3


class ChatterBotFactory:
	@staticmethod
	def create(type, *args):
		if type == ChatterBotType.CLEVERBOT:
			return Cleverbot()
		# elif type == ChatterBotType.JABBERWACKY:
		# 	return Cleverbot(base_url="http://jabberwacky.com", service_url="http://jabberwacky.com/webservicemin", end_index=29)
		elif type == ChatterBotType.PANDORABOT:
			if len(args) != 1:
				raise ChatterBotException("Pandorabot needs a Bot ID argument try visiting here: %s." % ("http://pandorabots.com/botmaster/en/mostactive"))
			return Pandorabot(*args)
		return None


#################################################
# Cleverbot impl
#################################################


class Cleverbot(object):
	def __init__(self, base_url="http://www.cleverbot.com", service_url="http://www.cleverbot.com/webservicemin?uc=165", end_index=35):
		self.service_url = service_url
		self.end_index = end_index

		self.data = OrderedDict()
		self.data['stimulus'] = ""
		self.data['islearning'] = "1"
		self.data['icognoid'] = "wsf"
		self.session = requests.Session()
		self.session.timeout = 10
		r = self.session.get(base_url)
		if r.status_code != 200:
			raise ResponseException(r)

	def think(self, text):
		self.data['stimulus'] = text
		data = urlencode(self.data)
		print(data[9:self.end_index])
		data += '&icognocheck=' + hashlib.md5(data[9:self.end_index].encode('utf-8')).hexdigest()
		r = self.session.post(self.service_url, data=data)
		if r.status_code != 200:
			raise ResponseException(r)
		response_values = GettableList(r.text.split("\r"), default='')
		self.data['sessionid'] = response_values.get(1)
		self.data['logurl'] = response_values.get(2)
		self.data['vText8'] = response_values.get(3)
		self.data['vText7'] = response_values.get(4)
		self.data['vText6'] = response_values.get(5)
		self.data['vText5'] = response_values.get(6)
		self.data['vText4'] = response_values.get(7)
		self.data['vText3'] = response_values.get(8)
		self.data['vText2'] = response_values.get(9)
		self.data['prevref'] = response_values.get(10)
		return response_values.get(0)

#################################################
# Pandorabots impl
#################################################


class Pandorabot(object):
	def __init__(self, botid):
		self.data = {
			"botid": botid,
			"custid": uuid.uuid1()
		}

	def think(self, text):
		self.data['input'] = text
		r = requests.post('http://www.pandorabots.com/pandora/talk-xml', params=self.data)
		if r.status_code != 200:
			raise ResponseException(r)
		text = etree.fromstring(r.text).find('that').text
		return text if text is not None else ''
