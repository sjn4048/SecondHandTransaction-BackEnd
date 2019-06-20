from flask import request, render_template, url_for, flash, redirect
from flask_login import login_required, login_user, logout_user
from ThriftShop.forms import LoginForm
from flask_login import current_user
import re

from ThriftShop import app, db
from ThriftShop.models import User


@app.route('/')
def index():
    if current_user.is_authenticated:
        return 'hahaha,secret'
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

        new_user = User(username=username, email=email)
        new_user.set_password(password)
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
        if not username or not password:
            flash('Invalid input.')
            return '', 204

        user = User.query.filter_by(username=username).first()
        if user is not None and user.validate_password(password):
            login_user(user)
            flash('Welcome back!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password. Please retry.', 'danger')
            return '', 204

    form = LoginForm()
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have already logout.', 'success')
    return redirect(url_for('index'))


@app.route('/home')
@login_required
def home():
    return 'My Home!'


# 功能函数
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
        return False, 'Username already existed.'
    user = User.query.filter_by(email=email).first()
    if user is not None:
        return False, 'E-mail already existed.'

    return True, None
