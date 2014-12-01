import requests
import json
from intro_to_flask import app
from flask import render_template, request, flash, redirect, session, url_for, jsonify
from forms import SignupForm, SigninForm, ClientForm
#from flask.ext.mail import Message, Mail
from models import db, User, Client
from werkzeug.security import gen_salt

#oauth = OAuth2Provider(app)

def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None

#basic views

@app.route('/', methods = ['GET', 'POST'])
def home():
  user = current_user()
  return render_template('home.html')


@app.route('/about')
def about():
  return render_template('about.html')

#oauth stuff...

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
          redirect_uri=form.redirect_url.data,
          default_scopes='email',
          )
          db.session.add(newclient)
          db.session.commit()
          return jsonify(
            client_id=newclient.client_id,
            client_secret=newclient.client_secret,
            )
    else: return render_template('client.html', form=form)


@app.route('/api/furz')
def furz():
    return jsonify({'furz':4})


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

if __name__ == '__main__':
  app.run(debug=True)


"""

@oauth.clientgetter
def get_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


@oauth.grantgetter
def grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()

@oauth.grantsetter
def set_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],#wtf
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant

@oauth.tokengetter
#def load_token(access_token=None, refresh_token=None):
def bearer_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
#def save_token(token, request, *args, **kwargs):
def set_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    )
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok

@app.route('/oauth/token', methods=['POST'])
@oauth.token_handler
def access_token():
    return None


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
def authorize(*args, **kwargs):
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        kwargs['user'] = user
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@app.route('/api/me')
@oauth.require_oauth()
def me():
    user = request.oauth.user
    #flash('this is weirdooo')
    #return jsonify(username=user.username)
    return jsonify({'jack': user.username, 'sape': 4139})

"""
