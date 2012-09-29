	#!/usr/bin/env python
# -*- coding: utf8 -*-
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import webapp2
import os
import jinja2
import random
import string
from pybcrypt import bcrypt
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class MyUser (db.Model):			#!!!доработать что бы тип для каждого поля получался из модели html!!!		
	username = db.StringProperty ()
	created = db.DateTimeProperty(auto_now_add = True)		
	user_hash = db.StringProperty ()
	email = db.StringProperty ()
	error = None
	cookie = {}

	def read_user (self, Handler=None, **kw):
		if Handler: #если метод вызывается для экземпляра Handler, значит юзер залогинен - читаем из кук			
			if Handler.request.cookies.get('usr'):
				self.cookie['usr'], self.cookie['hsh'] = Handler.request.cookies.get('usr').split('|')#{'usr': Handler.request.cookies.get('usr'),'hsh': Handler.request.cookies.get('hsh')}
			else: 
				self.login_error = "NotLogin"
			
			if self.cookie:
				check = db.GqlQuery("SELECT * FROM MyUser WHERE username = :1", self.cookie['usr']).get()
				if check and check.user_hash == self.cookie['hsh']:		#сравниваем хеш из куки и хеш из БД										
					for user_data in check._entity: #перекачиваем данные в объект пользователя
						setattr (self, user_data, check._entity[user_data])
					return True	#найден пользователь и хеш совпадает
				else:
					return None
			else:
				self.login_error = "CookieError"

		else: #если вызывается без указания, то читаем из формы	- логин и регистрация юзера
			if not ('username' in kw and 'password' in kw) and not (kw['username'] and kw['password']):#проверяем еще раз что есть пароль и имя - обязательные поля
				self.error = "Missing required values!"			
				return None
			else:						
				for user_data in kw:
					setattr (self, user_data, kw[user_data])
				return True

	def create_profile (self):#создать запись пользователя в бд 		
		self.user_hash = self.make_hash(self.username, self.password) #делаем хеш								
		check = db.GqlQuery("SELECT * FROM MyUser WHERE username = :1", self.username).get()		
		if check:
			self.error = 'ExistUserError'
			return None			
		else:
			self.put()
			self.id = str (self.key().id())			
			return True
			
		


	def login (self, Handler):# логин пользователя. установка кук, обновление базы и т.п. и т.п.	
		
		if not self.user_hash: #хеша нет, значит это логин(при регистрации хеш создается в create_profile), нужно сделать хеш и сравнить с тем что в базе
			
			check = db.GqlQuery("SELECT * FROM MyUser WHERE username = :1", self.username).get()#ищем запись пользователя БД по имени
			if check: #запись найдена
				if not self.valid_pw(self.username, self.password, check.user_hash): #проверка хеша
					self.error = "WrongUsernamePassword"
					return None
				else:
					for user_data in check._entity: #перекачиваем данные в объект пользователя
						setattr (self, user_data, check._entity[user_data])

			else: 
				self.error = "UserNotFound"
				return None

		h = str(self.username)+"|"+str(self.user_hash)
		Handler.response.headers.add_header('Set-Cookie', 'usr = %s; Path=/' % h)
		return "Ok"		

	def logout (self, Handler):#логаут пользователя. очистка кук
		Handler.response.headers.add_header('Set-Cookie', 'usr =; Path=/')

	def make_hash (self, name, pw):    	     		
 		return bcrypt.hashpw(pw+name, bcrypt.gensalt())

	def valid_pw (self, name, pw, h):
		if bcrypt.hashpw(pw+name, h) == h:
			return True

class Handler(webapp2.RequestHandler):

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
	
	def render (self, template, **kw):
		self.response.out.write(self.render_str(template, **kw))

	def get_form (self):		
		
		for arg in self.request.arguments():
		 	self.form_values[arg] = self.request.get(arg)					
		if not self.form_values['username']: self.form_values['error'] = "UsernameError"#-------------------проверяем есть ли ошибки в -------------
		elif not 'password' in self.form_values or not self.form_values['password']: self.form_values['error'] = "PasswordError"#-----------------данных полученных из формы--------------
		elif self.request.path == '/signup': 
			if not self.form_values['password'] == self.form_values['verify']: self.form_values['error'] = "VerifyError"#----------------------------------------------если есть - выдаем код ошибки------------
		else: 
			self.form_values['error'] = None

class Signup (Handler):

	error = ""
	form_values = {}

	def render_regform (self, **kw):
		self.render("signup.html", **kw)			

	def get(self):
		self.render_regform ()

	def post(self):
		self.form_values['error'] = ""
		self.get_form()		
		
		if self.form_values['error']:#если есть код ошибки (ошибка в полученных данных)			
			self.render_regform (**self.form_values)#ещё раз выводим форму регистрации уже с введенными данными и передаем в модель код ошибки
		
		else: # если ошибок в присланных данных нет, то			
			new_user = MyUser() # создаем объект пользователя

			new_user.read_user(**self.form_values)# заполняем объект параметрами из формы			
			
			if not new_user.create_profile():# создаем запись в БД и проверяем результат
				self.form_values['error'] = new_user.error				
				self.render_regform (**self.form_values)#если ошибка то ещё раз выводим форму регистрации уже с введенными данными и передаем в модель код ошибки
			else:
				self.write("<p>Отладочная информация <br></p><pre>")
				self.write("Пользователь с именем "+str(new_user.username)+" создан")
				self.write("</pre>")
				new_user.login(self)
				self.redirect('/welcome')

class Welcome (Handler):

	def render_welcome (self, **kw):
		self.render("welcome.html", **kw)

	def get(self):
		my_user = MyUser()		
		if my_user.read_user(self):#читаем пользователя из базы через кукис	
			self.render_welcome(username = my_user.username)			
		else: 
			self.redirect('/signup')

class Login (Handler):

	form_values = {}
	
	def render_login (self, **kw):
		self.render("login.html", **kw)

	def get(self):
		self.render_login()

	def post(self):
		my_user = MyUser()
		self.form_values['error'] = ""
		self.get_form()		
		
		if self.form_values['error']:#если есть код ошибки (ошибка в полученных данных)			
			self.render_login (**self.form_values)#ещё раз выводим форму регистрации уже с введенными данными и передаем в модель код ошибки
		else:
			my_user.read_user(**self.form_values)
			if not my_user.login(self) == "Ok":
				self.write('<pre>Логин не состоялся</pre>')
				self.write(my_user.error)
			else: 
				self.redirect('/welcome')

class Logout (Handler):

	def get(self):
		my_user = MyUser()		
		#my_user.read_user(self) # можно было пропустить этот шаг и сразу делать логаут, но оставил его на будущее (что бы что то записывать в БД перед логаутом)
		my_user.logout(self)		
		self.redirect('/signup')

	

app = webapp2.WSGIApplication([('/signup', Signup),
								('/welcome',Welcome),
								('/login', Login),
								('/logout', Logout)],
                              debug=True)




