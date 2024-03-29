from flask import Flask
 
app = Flask(__name__)
app.secret_key = 'development key'
 
import intro_to_flask.routes

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:R1kuchen@localhost/development'

from models import db
db.init_app(app)
with app.app_context():
   db.create_all()

import intro_to_flask.routes

#things neede for sending emails. I hope I won't need that in here. 

#app.config["MAIL_SERVER"] = "smtp.gmail.com"
#app.config["MAIL_PORT"] = 465
#app.config["MAIL_USE_SSL"] = True
#app.config["MAIL_USERNAME"] = 'contact@example.com'
#app.config["MAIL_PASSWORD"] = 'your-password'
#from routes import mail
#mail.init_app(app)
