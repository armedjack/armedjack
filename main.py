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
import datetime
from google.appengine.ext import db
from google.appengine.api import memcache

from pybcrypt import bcrypt
import pytils
import gmemsess

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))#,
							   #autoescape = True)
SESSION_EXPIRES = 3 #сколько дней храним сессию

permits = {#!!!!!!!!!!необходимо убрать хардкод и хранить разрешения в бд
			'admin'		: {'blog_post':True, 'comment_post':True,'power_control':True},
			'blogger'	: {'blog_post':True, 'comment_post':True,'power_control':False},
			'member'	: {'blog_post':False, 'comment_post':True,'power_control':False},
			'guest'		: {'blog_post':False, 'comment_post':False,'power_control':False}
	
}


app_path = {'main'	: '/',
			'login'	: '/login',
			'signup': '/signup',
			'logout': '/logout',
			'blog'	: '/blog',
			'profile': '/profile',
			'comment': '/comment',
			'ajax'	: '/ajx'
			}
secret = '_Long_123_Secret_456_String_789_' #следует сохранить отдельно

##########################################################################
#Вспомогательные функции #
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


def clone_entity(e, **extra_args): #клон сущности
	klass = e.__class__  #получаем класс сущности который копируем
	props = dict((k, v.__get__(e, klass)) for k, v in klass.properties().iteritems()) #копируем значения свойств из старой сущности в словарь
	props.update(extra_args) #обновляем созданный словарь значениями из аргументов функции
	return klass(**props) # создаем новую сущность и возвращаем её

USER_RE = re.compile(r"^[\w-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return email and EMAIL_RE.match(email)

#########################################################

class Nestedobject (object):

	def __init__ (self, m, r, nest_level = 0):
		self.msg = m
		self.replies = r
		self.nest_level = nest_level # иерархический уровень комментария (нужно для определения какого уровня не делаем отступ в html-шаблоне)
			
def nest (flow, root_rep_id_list, deep = 0): #рекурсивное создание древовидной структуры из плоского списка предков и потомков
	msglist = []
	nested_comments = []
	deep += 1 #глубина рекурсии = иерархический уровень комментария

	for rep_id in root_rep_id_list: #с помощью полученного списка ключей корневых ответов ветки составляем список объектов-ответов выбирая из плоского списка
		if rep_id in flow:
			msglist.append(flow[rep_id])		

	for msg in msglist: # добавляем к массиву-результату сообщения. если у них есть ответы (replies), то вызываем рекурсивно функцию, со списком ключей ответов. если нет ответов то присваеваем значение None
		nested_comments.append(Nestedobject (msg, nest(flow, msg.replies, deep) if msg.replies else None, deep))
		logging.error(msg.replies)		
	return nested_comments


#########################################################

##########################################################################
#Модель пользователя
##########################################################################

def users_key(group = 'default'): #задает путь к сущности(для разделения по группам)
	return db.Key.from_path('users', group)


class Group (db.Model):
	name = db.StringProperty(required = True)

	@classmethod
	def by_name(cls, name): # возвращает объект содержащий сущность из datastore с указанным именем
		u = Group.all().filter('name =', name).get()
		return u


class User(db.Model):
	"""Класс для модели пользователя для сохранения и получения 
					данных из datastore(и ни для чего другого)"""

	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	register = db.DateTimeProperty(auto_now_add = True)
	email = db.StringProperty()
	power = db.StringProperty()
	comments = db.IntegerProperty()
	posts = db.IntegerProperty()
	
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
					 email = email, 
					 power = 'member')

	@classmethod
	def check_user(cls, name, pw): #проверка: 1) пользователь существует 2) пароль совпадает
		u = cls.by_name(name)
		if u and valid_hash(u.pw_hash, name, pw):
			return u

	
	def set_power (self, power):
		
		self.power = power
		if self.put(): return True
		else: return False

	def check_power (self, action):
		if self.power == None: return False
		return permits[self.power][action]#!!!!!!!!!!необходимо убрать хардкод и хранить разрешения в бд


			
##########################################################################
#Модель поста
##########################################################################

class BlogEntry (db.Model):

	def make_rudate(self, date_set = None):			

		if not date_set: return pytils.dt.ru_strftime(u"%d %b %Y %H"+u":"+u"%M",inflected=True, date=self.created)

		day, month, year, hm = re.split(' ', pytils.dt.ru_strftime(u"%d %b %Y %H"+u":"+u"%M",inflected=True, date=self.created))		
		if date_set == 'day' or 'month' or 'year': return vars()[date_set]
		else: return 'Date Error'		

	def make_rucomment(self, com_number):
		return  pytils.numeral.get_plural(0, u"Комментарий, Комментария, Комментариев", absence=u"Комментариев пока нет")

class Post (BlogEntry):
	title = db.StringProperty(required = True)
	text = db.TextProperty(required = True)
	comments = db.IntegerProperty(default = 0)
	author = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	replies = db.ListProperty(int)

class Comment (BlogEntry):
	text = db.TextProperty(required = True)
	author = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	replies = db.ListProperty(int)
##########################################################################
#Модели сраниц
##########################################################################
class MainHandler(webapp2.RequestHandler):
	"""Базовый класс для обработчиков запросов браузера
		write() - отправляет аргументы на вывод браузеру
		render_str() - перегрузка технической функции(добавление параметра "имя пользователя")
		render() - отправляет шаблон на вывод браузера(предварительно вызывает рендер шаблона render_str)
	"""
	
	def write(self, *a, **kw): #вывод текста на экран
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params): # добавление различных параметров в рендер шаблона 
		params['user'] = self.user
		params.update(app_path)		
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
		self.set_cookie('ssid', ssid, expires=SESSION_EXPIRES)		
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
		self.user = uid and User.by_id(int(uid))
		if self.user is not None: #если пользователь существует сохраняем в объект его uid из датастора
			self.user.uid = int(uid)
			
	
class Blog(MainHandler):	
	def get(self, owner = "Spinningmill", page = 1):				
		text_flow = Post.all().ancestor(users_key(owner)).order('-created').fetch(10)		
		if text_flow: 
			for msg in text_flow:
				if len(msg.text) > 1000:
					msg.text = msg.text[0:1000] + "..."
			self.render("blog.html", text_flow = text_flow, owner = owner)
		else: 
			text_flow = {'error':u'Пусто'}
			self.render("blog.html", text_flow = text_flow)

	def post(self, owner = "Spinningmill", page = 1):
		title = self.request.get("subject")
		text = self.request.get("content")
		if self.user and self.user.check_power('blog_post'): #может ли юзер постить
			if title and text:
				a = Post(parent = users_key(self.user.name), title = title, text = text, author = self.user.name)
				a.put()
				msg_id = str (a.key().id())				
				self.redirect(app_path['main'])
				
			else:
				error = "We need some text and it's title. Both."
				self.render_front(title = title, text = text, error = error)
		else:
			self.redirect(app_path['login'])

class PostHandler (MainHandler):

	def make_path(self, post_id, id_string):
		path = ['Post', int(post_id)] #путь всегда начинается с поста к которому коментарии
		if id_string:#если строка с id пустая, значит родителем будет пост, если не пустая, то добавляем всех по очереди к пути
			id_list = re.split(',', id_string)		
			for comm_id in id_list:
				path +=['Comment', int(comm_id)]
		return path

	def add_reply(self, post_id, id_string):
		text = self.request.get("content")		
		if text:
			p = Post.get_by_id(int(post_id), parent = users_key(owner))

			if id_string:#если строка с id предков не пустая, то собираем ключ из id всех родителей
				parent_path = self.make_path(post_id, id_string)#собираем путь до сущности родителя из id переданных из браузера
				parent_key = db.Key.from_path(*parent_path)	#создаем из пути ключ
				parent = db.Model.get(parent_key) #получаем сущность предка из датастора
			else: parent = p #если строка с id пустая, значит родителем будет пост, его сущность уже получена ранее

			c = Comment (parent = parent, text = text, author = self.user.name)# сохраняем комментарий
			c.put()
			
			parent.replies.append(c.key().id())#добавляем ответ к списку коментариев-потомков(ответов) родителя
			p.comments +=1		#увеличиваем счетчик комментариев в посте
			#!!!сделать проверку успешной записи комментария и если ок, то увеличить счетчик комментариев.
			
			p.put()			
			if p != parent: parent.put() #если родитель не пост, то тоже его сохраняем
			return c
		else:
			self.redirect(app_path['main'])#!!!!!!обработка ошибки пустого текста
	
	def get (self,  owner, post_id, com_id): #выводим пост с комментариями
		p=Post.get_by_id(int(post_id), parent = users_key(owner))		
		if p:
			com_flow = Comment.all().ancestor(p)

			com_index = {}
			root_com_list = []
			for com in com_flow:
				com_index[com.key().id()] = com #создаем хеш ключ:объект (индекс по ид)					

			nested_comments = nest (com_index, p.replies)			
			self.render("post.html", msg = p, com_flow = nested_comments, owner = owner)
		


	def post (self,  owner, post_id, comment_id): #добавляем комментарий
		if self.user and self.user.check_power('comment_post'):			
			self.add_reply (post_id, comment_id)					
			self.redirect('/'+owner+app_path['blog']+'/'+post_id)
		else:
			self.redirect(app_path['login'])

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
			params['error_username'] = True
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = True
			have_error = True

		elif self.password != self.verify:
			params['error_verify'] = True
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = True			
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


class AjaxHandler(PostHandler):

	def post(self, case, post_id):

		if self.user:
			if case == 'addreply':			
				tribe_id = self.request.get('ancestors') #список id предков			
				if self.user.check_power('comment_post'):
					text = self.request.get("content")				
					c = self.add_reply (post_id, tribe_id)
					self.render('reply.html', com = c, nest_level = len(re.split(',',tribe_id)))
				else:
					self.render('reply.html', com = "Error", nest_level = len(re.split(',',tribe_id)))
				#self.write('Hello from server! We get and save: '+text)
			else:
					self.render('reply.html', com = "Error", nest_level = len(re.split(',',tribe_id)))


class Profile(MainHandler):

	def get(self):
		#вывод странички с данными пользователя
		pass

class Maintance (MainHandler):

	def get(self):
		
		if self.user and self.user.power == 'admin':
			username = self.request.get('username')
			power = self.request.get('power')
			if power and username:
				user = User.by_name(username)
				user.set_power(power)			
				output = u"<p>Пользователь %s включен в группу %s </p>" % (user.name, user.power)
				
			else:
				output = u"<p>Ничего </p>"

			self.render('mnt.html', output = output)

		####
		#pass
		else:
			self.redirect(app_path['main'])

		


		# posts = Post.all()
		# output = ''
		# temp = ''
		# for p in posts:			
		# 	output += u"<br><b>Пост #</b>"+str(p.key().id())+"<br>"
		# 	com_flow = Comment.all().ancestor(p)			

		# 	for com in com_flow:
		# 		output += u"<br> Комментарий #"+str(com.key().id())+"<br>"
		# 		descendants = Comment.all().ancestor(com)
		# 		com.replies = []
		# 		for d in descendants:
		# 			output += u"<br> Комментарий #"+str(com.key().id())+"<br>"
		# 			if com.key() == d.parent_key() :						
		# 				com.replies.append(d.key())
		# 				temp = com.key()
						
		# 			com.put()

		# t = Comment.get(temp)
		# rr = Comment.get(t.replies[0])
		# logging.error(rr.author)



		


	
logging.getLogger().setLevel(logging.DEBUG)
app = webapp2.WSGIApplication([(app_path['main'], Blog)
								,('/([\w-]{3,20})' +app_path['blog']+'/*', Blog)
								,('/([\w-]{3,20})' +app_path['blog']+'/page/([0-9]+)/*', Blog)
								,('/([\w-]{3,20})'+app_path['blog']+'/([0-9]+)/*(.+)*', PostHandler)								
								,('/([\w-]{3,20})' +app_path['profile']+'/*', Profile)
								,(app_path['signup']+'/*',Signup)
								,(app_path['login']+'/*', Login)								
								,(app_path['logout']+'/*', Logout)
								,(app_path['ajax']+'/(.+)/([0-9]+)', AjaxHandler)
								,('/mnt', Maintance)
								],
							  debug=True)




 