# gmemsess.py - memcache-backed session Class for Google Appengine
# -*- coding: utf8 -*-
# Version 1.4
#	Copyright 2008 Greg Fawcett <greg@vig.co.nz>
#
#	This program is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program.  If not, see <http://www.gnu.org/licenses/>.

import random
import string

import logging
import pickle
import datetime
from google.appengine.api import memcache
from google.appengine.ext import db

_sidChars = string.ascii_letters + string.digits
_defaultTimeout=72*60*60 # 3 days
_expires_datetime = datetime.datetime.now() + datetime.timedelta(seconds=_defaultTimeout)
_expires= _expires_datetime.strftime('%a, %d %b %Y %H:%M:%S GMT')#Пока нет записи в датастор, а только в мемкэш больше трех дней не стоит делать.
_defaultCookieName='sid'



class SessionModel(db.Model):    
    datadump = db.BlobProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    expires = db.DateTimeProperty()
#----------------------------------------------------------------------
class Session(dict):
	"""A secure lightweight memcache-backed session Class for Google Appengine."""

	#----------------------------------------------------------
	def __init__(self,rh,name=_defaultCookieName,timeout=_defaultTimeout):
		"""Create a session object.

		Keyword arguments:
		rh -- the parent's request handler (usually self)
		name -- the cookie name (defaults to "gsid")
		timeout -- the number of seconds the session will last between
		           requests (defaults to 1800 secs - 30 minutes)
		"""
		self.rh=rh	# request handler
		self._timeout=timeout
		self._name=name
		self._new=True
		self._invalid=False
		dict.__init__(self)		
		if name in rh.request.str_cookies:			
			self._sid=rh.request.str_cookies[name]			
			data=memcache.get(self._sid)		

			if data is None:# если нет в memcache проверяем datastore
				logging.error('Hit Datastore!')
				ds_session = SessionModel.get_by_key_name(self._sid)
				if ds_session is not None:# если в датасторе есть такая сессия, читаем данные
					data = pickle.loads(ds_session.datadump)

			if data!=None: #если данные есть, то обновляем таймаут в memcache и expires в dstastore
				self.update(data)				
				memcache.set(self._sid,data,self._timeout) # memcache timeout is absolute, so we need to reset it on each access				
				self.ds_update(data,_expires_datetime)# обновляем expires в datastore								
				self._new=False
				return

		# Create a new session ID
		# There are about 62^256 combinations, so guessing won't work
		self._sid="".join(random.choice(_sidChars) for i in range (256))

		# Added path so session works with any path
		rh.response.headers.add_header('Set-Cookie','%s=%s; expires=%s; path=/;'%(name,self._sid, _expires))

	#----------------------------------------------------------
	def ds_update (self, data, expires):
		datadump = pickle.dumps(data,2)	
		ds_session = SessionModel.get_or_insert(key_name = self._sid)
		ds_session.datadump = datadump 
		ds_session.expires = expires				
		ds_session.put()

	#----------------------------------------------------------
	def save(self):
		"""Save session data."""		
		if not self._invalid:
			memcache.set(self._sid,self.copy(),self._timeout)

	#----------------------------------------------------------
	def is_new(self):
		"""Returns True if session was created during this request."""
		return self._new

	#----------------------------------------------------------
	def get_id(self):
		"""Returns session id string."""
		return self._sid

	#----------------------------------------------------------
	def invalidate(self):
		"""Delete session data and cookie."""
		self.rh.response.headers.add_header('Set-Cookie',
				'%s=; expires=Sat, 1-Jan-2000 00:00:00 GMT;'%(self._name))
		memcache.delete(self._sid)
		#удаляем запись из датастора##################################################################################
		self.clear()
		self._invalid=True
