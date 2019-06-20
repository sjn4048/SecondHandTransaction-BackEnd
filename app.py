from flask import Flask, request, render_template, url_for, flash, redirect
from flask_login import login_required, login_user, logout_user, LoginManager, UserMixin
from forms import LoginForm
from flask_sqlalchemy import SQLAlchemy
from models import User
from ext import db, login_manager
from hashlib import md5
import re
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





@app.route('/')
def index():
    # TODO
    return render_template('index.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        # TODO: check if information is valid
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        valid, info = __check_register_info(username, password, email)
        if not valid:
            flash('%s Please retry.' % info, 'danger')
            return '', 204

        new_user = User(username=username, password=password, email=email)
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('Success! Redirecting to login page...', 'success')
            return redirect(url_for('login'))
        except:
            flash('Email or username already used. Please retry.', 'danger')
    else:
        return render_template('register.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    # TODO 也可以用邮箱登录
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user is not None:
            login_user(user)
            flash('Welcome back!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password. Please retry.', 'danger')
    form = LoginForm()
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have already logout.', 'success')
    return redirect(url_for('index'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=int(user_id)).first()


def __check_register_info(username, password, email):
    if len(username) <= 6 or len(username) > 20:
        return False, 'Username should be longer than 6 letters and shorter than 20 letters.'
    if len(password) <= 6 or len(password) > 20:
        return False, 'Password should be longer than 6 letters and shorter than 30 letters.'
    if len(password) <= 6 or len(password) > 20:
        return False, 'Password should be longer than 6 letters and shorter than 30 letters.'
    if re.search(r'\d', password) is None or re.search(r'[A-Za-z]', password) is None:
        return False, 'Password should contain both digit and letters.'
    user = User.query.filter_by(username=username).first()
    if user is not None:
        return False, 'Username already existed. Please try again.'
    user = User.query.filter_by(email=email).first()
    if user is not None:
        return False, 'E-mail already existed. Please try again.'

    return True, None


if __name__ == '__main__':
    app.run(debug=True)
