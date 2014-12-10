import urllib2
import requests
import json
from intro_to_flask import app
from flask import render_template, request, flash, redirect, session, url_for, jsonify
from forms import SignupForm, SigninForm, ClientForm, OauthForm, PostForm
#from flask.ext.mail import Message, Mail
from models import db, User, Client, Grant, Token, Post
from werkzeug.security import gen_salt
from sqlalchemy import update
from datetime import datetime, timedelta
import time, threading


#get the current user which is stored in the flask session - not working properly
def current_user():
    if 'email' in session:
        email = session['email']
        return User.query.filter_by(email=email).first()
    return None

#delete all grants and tokens that expired from the db, it should be called periodically. I tried to implement that with threading, but didn't work (hung) 
def expire():
  grants = Grant.query.all()
  count = len(grants)-1
  tok = grants[count]
  while (tok.expires - datetime.utcnow()) < timedelta(seconds=1):
  	tok = grants[count]
	db.session.delete(tok)
	if count == 0: break
	count=count-1
  tokens = Grant.query.all()
  count = len(tokens)-1
  tok = tokens[count]
  while (tok.expires - datetime.utcnow()) < timedelta(seconds=1):
  	tok = tokens[count]
	db.session.delete(tok)
	if count == 0: break
	count=count-1
  

@app.route('/', methods = ['GET', 'POST'])
def home():
  #call expired which deletes all the expired tokens and grants fromthe db 
  expire()  
  """user = current_user()
  flash(user.firstname)
  newuser = User('hand', 'friz', 'email@email.com', 'password')
  db.session.add(newuser)
  db.session.commit
  user = current_user()
  if user == None: flash('commit is the problem')
  else: flash(current_user().lastname)"""
  return render_template('home.html')


@app.route('/about')
def about():
  return render_template('about.html')

#oauth stuff...

#here a consumer can register and get a consumer id and secret
@app.route('/client', methods = ['GET', 'POST'])
def client():
    form = ClientForm(request.form)
    if request.method == 'POST':
	if form.validate() == False:
	  return render_template('client.html', form=form)
	else:
	  newclient = Client(
          client_id=gen_salt(40),
          client_secret=gen_salt(50),
	  client_name=form.name.data,
          redirect_uris=form.redirect_url.data,
          default_scopes='email',
          )
          db.session.add(newclient)
          db.session.commit()
          return jsonify(
            client_id=newclient.client_id,
            client_secret=newclient.client_secret,
            )
    else: return render_template('client.html', form=form)


#the consumer should send a request to that url with his id and 
@app.route('/oauth2/authorize')
def authorize():
  client_id =request.args['client_id'] 
  redirect_uri = request.args['redirect_uri']
  #this is not so nice, as the client needs to provide EXACTLY the same redirecturi... should check for the beginning.
  client1 = Client.query.filter_by(redirect_uris=redirect_uri).first()
  client2 = Client.query.filter_by(client_id=client_id).first()
  if client1 is None or client1 is not client2:
	return 'your client doesent exist!!!'
  else:
	#yep I'm not getting how to pass parameters so I set a global variable, I'd clearly prefer to pass it with the redirect but no matter what I do, it wont work. 
	global theclient
	theclient = client1
	return redirect(url_for('oauth_view'))

#to ask the user whether he wants to give the consumer access to his data
@app.route('/oauth_view', methods=['GET', 'POST'])
def oauth_view():
  form = OauthForm(request.form)
  if request.method == 'POST':
	if 'email' not in session:
	      session['email'] = form.email.data
	global theclient
	theclient.user_id = current_user().uid; 
	db.session.add(theclient)
	db.session.commit()
	return redirect(make_grant())       	
  elif request.method == 'GET':
	return render_template('oauth.html', form = form)

def make_grant():
  #find the client through the current user
  user =current_user() 
  #if user == None: return 'blalblabla'
  client = Client.query.filter_by(user_id=current_user().uid).first()
  otto = set_grant(client.client_id)
  return (client.redirect_uris+'?code='+otto.code)

def set_grant(client_id):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        user=current_user(),
        expires=expires,
	code=gen_salt(40)#clara that's probably not save enough
    )
    db.session.add(grant)
    db.session.commit()
    return grant

#the cosumer possesing a code can send a request in order to receive an access token 
@app.route('/oauth2/access', methods=['GET', 'POST'])
def access():
  client_id =request.args['client_id'] 
  redirect_uri = request.args['redirect_uri']
  client_secret=request.args['client_secret']
  code = request.args['code']  
  client = Client.query.filter_by(client_id=client_id).first()

  #what if the user falls out of the session because new request, so i just put him in here again identifying through the token
  grant = Grant.query.filter_by(code=code).first()
  user = User.query.filter_by(uid=grant.user_id).first()
  session['email'] =user.email 

  temp = False
  for grant in Grant.query.filter_by(client_id=client_id):
	if grant.code == code: 
	   temp = True
  if (client.client_secret == client_secret) and temp:
	#make access token and co and put it in a json and send!
	tok = make_token()
  	data ={'access_token':tok.access_token, 'token_type':'bearer','expires_in':tok.expires, 'refresh_token':tok.refresh_token}  
  	data_json = jsonify(data)
	return data_json
  else:
	return 'sorry you did not provide the correct keys...'


def make_token():
  #find the client through the current user
  user =current_user() 
  client = Client.query.filter_by(user_id=user.uid).first()
  otto = set_token(client.client_id)
  return otto

def set_token(client_id):
  # make sure that every client has only one token connected to a user
  client = Client.query.filter_by(client_id=client_id).first()
  toks = Token.query.filter_by(
        client_id=client_id,
        user_id=client.user_id
  )
  for t in toks:
     db.session.delete(t)

  tok = Token(
  client_id = client.client_id,
  user= client.user,
  token_type = 'bearer',
  access_token = gen_salt(40), #security!
  refresh_token = gen_salt(40),
  expires = datetime.utcnow() + timedelta(minutes=100)
  )
  db.session.add(tok)
  db.session.commit()
  return tok



"""theclient = None
theuser = None #yes this is very ugly, but the session stuff makes me go crazy!!they are both set at the beginning of an oauth process and set null again in the end. """


#sign in up out..

@app.route('/signup', methods=['GET', 'POST'])
def signup():
  form = SignupForm(request.form)
  if 'email' in session:
	return redirect(url_for('profile'))

  if request.method == 'POST':
	if form.validate() == False:
	  return render_template('signup.html', form=form)
	else:
	  newuser = User(form.firstname.data, form.lastname.data, form.email.data, form.password.data)
          db.session.add(newuser)
          db.session.commit()       
	  
	  session['email'] = newuser.email

          return redirect(url_for('profile')) 

  elif request.method == 'GET':
	return render_template('signup.html', form=form)

@app.route('/profile')
def profile():
  if 'email' not in session:
	return redirect(url_for('signin'))

  user = User.query.filter_by(email=session['email']).first()
  if user is None:
	return redirect(url_for('signin'))
  else:
	return render_template('profile.html')


@app.route('/signin', methods=['GET', 'POST'])
def signin():
  form = SigninForm(request.form)
  if 'email' in session:
	return redirect(url_for('profile'))

  if request.method == 'POST':
	if form.validate() == False:
	  return render_template('signin.html', form = form)
	else:
	  session['email'] = form.email.data
	  return redirect(url_for('profile'))
  elif request.method == 'GET':
	return render_template('signin.html', form=form)

@app.route('/signout')
def signout():
  if 'email' not in session:
	return redirect(url_for('signin'))
  session.pop('email', None)
  return redirect(url_for('home'))

#post stuff

#users can post a text through a form - at the moment it'll be shown through a flash )))
@app.route('/forum', methods=['GET','POST'])
def forum():
  posts =Post.query.all() 
  for post in posts:
	name = User.query.filter_by(uid = post.user_id).first().firstname
	flash(post.text + '   from   ' + name)
  form = PostForm(request.form)
  if request.method == 'POST':
	newpost = Post(current_user().uid, form.text.data, datetime.utcnow())
	db.session.add(newpost)
	db.session.commit()	
  return render_template('post.html', form=form)

#api stuff

#stupid test function

@app.route('/api/furz')
def furz():
    return jsonify({'furz':4})

#this is a method to reveive last x post without which user postet them,this method is open, the format is a json 0:newest post, 1:second newest post... the number of posts is specified in the header with number = x
@app.route('/api/posts')
def send_posts():
   posts = Post.query.all()
   nbr = request.args['number']
   t = int(nbr)
   posts = posts[-t :]
   x = {}
   y = 0
   for post in posts:
	x.update({y:post.text})
	y=y+1
   #xx = x[-nbr:]
   return jsonify(x)

#this is a method to reveive last x post from user y, it is protectet

#this is a method to receive the info of the user
@app.route('/api/me')
def send_me():
   at = request.args['token']
   tok = Token.query.filter_by(access_token=at).first()
   if tok == None:
	return jsonify({'ups':'you have no right to access this data'})
   else:
	user = User.query.filer_by(uid=tok.user_id).first()
	info = {'name':user.firstname, 'lastname':user.lastname, 'email':user.email}
	return jsonify({'ups':'you have right to access this data'})
   #return jsonify(info)

if __name__ == '__main__':
  app.run(debug=True)

