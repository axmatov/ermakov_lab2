#from flask.ext.sqlalchemy import SQLAlchemy
from werkzeug import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()

class User(db.Model):
  __tablename__ = 'users'
  uid = db.Column(db.Integer, primary_key = True)
  firstname = db.Column(db.String(100))
  lastname = db.Column(db.String(100))
  email = db.Column(db.String(120), unique=True)
  pwdhash = db.Column(db.String(54))
   
  def __init__(self, firstname, lastname, email, password):
    self.firstname = firstname.title()
    self.lastname = lastname.title()
    self.email = email.lower()
    self.set_password(password)
     
  def set_password(self, password):
    self.pwdhash = generate_password_hash(password)
   
  def check_password(self, password):
    return check_password_hash(self.pwdhash, password)

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.ForeignKey('users.uid'))
    user = db.relationship('User')
    text = db.Column(db.Text)
    tiemstamp = db.Column(db.DateTime)

    def __init__(self, user_id, text, timestamp):
	self.user_id = user_id
	self.text = text
	self.tiemstamp = timestamp

class Client(db.Model):
    __tablename__ = 'clients'
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), nullable=False)
    client_name = db.Column(db.String(40))

    #there will potentially be a lot of users...?? yes, but I only store them temporally, while getting a token. So for the moment, a client cannot receive access tokens for two users at the same time... 
    user_id = db.Column(db.ForeignKey('users.uid'))
    user = db.relationship('User')

    redirect_uris = db.Column(db.Text)
    default_scopes = db.Column(db.Text)

    @property
    def client_type(self):
        return 'public'
    """
    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []
    
    @property
    def default_redirect_uri(self):
        return self.redirect_uri

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []
    """

class Grant(db.Model):
    __tablename__= 'grants' 
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey('users.uid', ondelete='CASCADE')
    )
    user = db.relationship('User')

    client_id = db.Column(
        db.String(40), db.ForeignKey('clients.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    code = db.Column(db.String(255), index=True, nullable=False)

    expires = db.Column(db.DateTime)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self


class Token(db.Model):
    __tablename__='tokens'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('clients.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('users.uid')
    )
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

