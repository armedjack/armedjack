	#!/usr/bin/env python
# -*- coding: utf8 -*-
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0(the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	 http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import webapp2
import os
import re
import jinja2
import random
import string
import hmac
import logging
import gmemsess
import datetime
from pybcrypt import bcrypt
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)


app_path = {'main'	: '/',
			'login'	: '/login',
			'signup': '/signup'
			}
secret = '_Long_123_Secret_456_String_789_' #следует сохранить отдельно

##########################################################################
#Технические функции #
##########################################################################

def make_hash(*args): # создание хеша из полученных аргументов
	line_for_hashing = ""
	for arg in args:
		line_for_hashing += str(arg)
	return bcrypt.hashpw(line_for_hashing, bcrypt.gensalt())

def valid_hash(h, *args): # проверка хеша
	line_for_hashing = ""
	for arg in args:
		line_for_hashing += str(arg)
	if bcrypt.hashpw(line_for_hashing, h) == h:
			return True

def make_secure_val(val): #простое хеширование параметра(на выходе параметр|хеш)
	return '%s|%s' %(val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val): #проверка соответствия параметр-хеш
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

def render_str(template, **params): #подготовка шаблона
	t = jinja_env.get_template(template)
	return t.render(params)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

##########################################################################
#Модель пользователя
##########################################################################

def users_key(group = 'default'): #задает путь к сущности(для разделения по группам)
	return db.Key.from_path('users', group)

class User(db.Model):
	"""Класс для модели пользователя для сохранения и получения 
					данных из datastore(и ни для чего другого)"""

	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid): # возвращает объект содержащий сущность из datastore с указанным id
		return User.get_by_id(uid, parent = users_key()) 

	@classmethod
	def by_name(cls, name): # возвращает объект содержащий сущность из datastore с указанным именем
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):# создает объект-модель для записи в datastore
		pw_hash = make_hash(name, pw)
		return User(parent = users_key(),
					 name = name,
					 pw_hash = pw_hash,
					 email = email)

	@classmethod
	def check_user(cls, name, pw): #проверка: 1) пользователь существует 2) пароль совпадает
		u = cls.by_name(name)
		if u and valid_hash(u.pw_hash, name, pw):
			return u
			
##########################################################################
#Модель поста
##########################################################################
class Post (db.Model):
	title = db.StringProperty(required = True)
	text = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)


##########################################################################
#Модели сраниц
##########################################################################
class MainHandler(webapp2.RequestHandler):
	"""Базовый класс для обработчиков запросов браузера
		writ() - отправляет аргументы на вывод браузеру
		render_st() - перегрузка технической функции(добавление параметра "имя пользователя")
		render() - отправляет шаблон на вывод браузера(предварительно вызывает рендер шаблона render_str)
	"""
	
	def write(self, *a, **kw): #вывод текста на экран
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params): # добавление имени пользователя в рендер шаблона
		params['user'] = self.user
		return render_str(template, **params) # вызов технической функции с новым параметром

	def render(self, template, **kw): # вывод шаблона на экран
		self.write(self.render_str(template, **kw))

	def set_cookie(self, name, val, expires): # установка куки для сессии			
		expires = (datetime.datetime.now() + datetime.timedelta(days=expires)).strftime('%a, %d %b %Y %H:%M:%S GMT')#Пока нет записи в датастор, а только в мемкэш больше трех дней не стоит делать.
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; expires=%s; Path=/' %(name, val, expires))

	def read_secure_cookie(self, name): #чтение сессионной куки
		cookie_val = self.request.cookies.get(name)		
		return cookie_val and check_secure_val(cookie_val)

	def check_session(self):		
		if self.session.is_new():			
			return None
		cookie_val = self.request.cookies.get('ssid') #хеш из uid и ip
		if valid_hash(cookie_val, self.session['uid'], self.request.remote_addr):			
			return self.session['uid']
		else: 
			return None
	
	def login(self, user): #логин пользователя (установка сессионной куки)

		ssid = make_hash(user.key().id(), self.request.remote_addr)
		self.set_cookie('ssid', ssid, expires=3)		
		self.session['uid'] = user.key().id()

		self.session['ssid'] = ssid
		self.session.save()

	def logout(self): #логаут
		# self.response.headers.add_header('Set-Cookie', 'uid=; Path=/')
		self.session.invalidate()

	def initialize(self, *a, **kw):

		webapp2.RequestHandler.initialize(self, *a, **kw)
		#uid = self.read_secure_cookie('user_id')		
		self.session = gmemsess.Session(self)
		uid = self.check_session()
		logging.error(uid)
		self.user = uid and User.by_id(int(uid))
		
	
class Front(MainHandler):
	"""Модель для главной страницы"""
	def get(self):
		if self.user: 
			text_flow = db.GqlQuery("select * from Post order by created desc limit 10")
			if text_flow: self.render("front.html", text_flow = text_flow)
		else:
			self.redirect(app_path['login'])

	def post(self):
		title = self.request.get("subject")
		text = self.request.get("content")
		
		if title and text:
			a = Post(title = title, text = text)
			a.put()
			msg_id = str (a.key().id())
			# self.redirect("/blog/%s" %msg_id)
			self.redirect(app_path['main'])
			
		else:
			error = "We need some text and it's title. Both."
			self.render_front(title = title, text = text, error = error)

class PostHandler (MainHandler):
	
	def get (self, post_id):
		p=Post.get_by_id(int(post_id))
		if p:
			self.render("post.html", text = p.text, title = p.title)

class Signup(MainHandler):
	"""Модель для страницы регистрации"""
	def get(self):
		self.render("signup.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
					  email = self.email) #cохраняем параметры для передачи обратно в форму в случае ошибки

		if not valid_username(self.username):
			params['error_username'] = u"Это не подходящее имя пользователя."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = u"Пароль не подходит. Попробуйте ещё раз."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = u"Введенные пароли не совпадают. А должны бы."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = u"Это не правильный адрес e-mail."
			have_error = True

		if have_error:
			self.render('signup.html', **params)
		else:
			self.done()

	def done(self):
		#проверяем что такой пользователь не существует
		u = User.by_name(self.username)
		if u:
			msg = u"Пользователь с таким именем уже есть."
			self.render('signup.html', error_username = msg)
		else:			
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			self.redirect(app_path['main'])

class Login(MainHandler):
	"""Модель для страницы входа"""
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.check_user(username, password)
		if u:
			self.login(u)
			self.redirect(app_path['main'])
		else:
			error = u"Имя пользователя или пароль введены не верно."
			self.render ('login.html', error = error)


class Logout(MainHandler):
	"""Модель для страницы выхода"""
	def get(self):
		self.logout()
		self.redirect(app_path['main'])

	
logging.getLogger().setLevel(logging.DEBUG)
app = webapp2.WSGIApplication([(app_path['main'], Front)
								,(app_path['signup'],Signup)
								,(app_path['login'], Login)
								#,('/blog/([0-9]+)', PostHandler)
								,('/logout', Logout)
								],
							  debug=True)




