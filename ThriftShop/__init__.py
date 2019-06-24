from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_cors import CORS

from ThriftShop import config

app = Flask(__name__)
app.config.from_object(config)

CORS(app, resources=r'/*')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please login first!'


@login_manager.user_loader
def load_user(user_id):
    from ThriftShop.models import User
    return User.query.filter_by(id=int(user_id)).first()


from ThriftShop import views, errors, commands
