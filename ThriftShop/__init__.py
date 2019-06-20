from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import sys
import os

app = Flask(__name__)
app.secret_key = 'th1s_1s_My_s3creT'

WIN = sys.platform.startswith('win')
if WIN:
    prefix = 'sqlite:///'
else:
    prefix = 'sqlite:////'
app.config['SQLALCHEMY_DATABASE_URI'] = prefix + os.path.join(app.root_path, 'database/users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please login first!'

@login_manager.user_loader
def load_user(user_id):
    from ThriftShop.models import User
    return User.query.filter_by(id=int(user_id)).first()

from ThriftShop import views, errors, commands