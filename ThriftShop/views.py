from flask import request, render_template, url_for, flash, redirect, jsonify, g
from flask_httpauth import HTTPTokenAuth
from flask_login import current_user
from flask_restful import inputs
import re
import os
from werkzeug.utils import secure_filename
from sqlalchemy import desc
import time
from datetime import datetime

from ThriftShop import app, db
from ThriftShop.models import User, BookInfo, Message, WantBuy, Order

auth = HTTPTokenAuth(scheme='token')


@app.route('/api/register', methods=['POST'])
def register():
    username = request.form.get('username', default=None)
    password = request.form.get('password', default=None)
    email = request.form.get('email', default=None)
    residence = request.form.get('residence[2]', default='')
    phone_number = request.form.get('phone', default=None)

    if any(x is None for x in (username, password, email, residence, phone_number)):
        return jsonify({'status': 0, 'msg': 'Please input all information required.'})

    valid, info = __check_register_info(username, password, email)
    if not valid:
        return jsonify({'status': 0, 'msg': info})

    new_user = User(username=username, email=email, residence=residence, phone_number=phone_number)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'status': 1, 'msg': info})


@app.route('/api/login', methods=['POST'])
def login():
    # TODO 也可以用邮箱登录
    username = request.form['username']
    password = request.form['password']
    if not username or not password:
        return jsonify({'status': 0, 'msg': 'Invalid input.', 'token': None})

    user = User.query.filter_by(username=username).first()
    if user is not None and user.verify_password(password):
        return jsonify({'status': 1, 'msg': 'Welcome back!', 'token': user.generate_token().decode('ascii')})
    else:
        return jsonify({'status': 0, 'msg': 'Invalid username or password.', 'token': None})


@app.route('/api/upload', methods=['POST'])
def upload():
    pic_file = request.files.get('file', default=None)
    if pic_file and allowed_file(pic_file.filename):
        folder = app.config['UPLOAD_PIC_PATH']
        if not os.path.isdir(folder):
            os.mkdir(folder)
        time_stamp = hex(int(time.time()))[-6:]
        pic_path = os.path.join(app.config['UPLOAD_PIC_PATH'], time_stamp + '_' + secure_filename(pic_file.filename))
        pic_file.save(pic_path)
        # TODO
        return jsonify({'status': 1, 'filename': pic_path[pic_path.index('/static'):]})
    else:
        print(request.files)
        return jsonify({'status': 0, 'filename': None})


@app.route('/api/logout')
@auth.login_required
def logout():
    return jsonify({'status': 1, 'msg': 'You have already logout. Goodbye~'})


@app.route('/api/user/<int:idx>')
@auth.login_required
def user_info(idx):
    # TODO
    user_dict = current_user.as_dict()
    del user_dict['password'], user_dict['id']

    return jsonify(user_dict)


@app.route('/api/post', methods=['POST'])
@auth.login_required
def post():
    # TODO 处理空请求
    book_name = request.form.get('book_name', default='[No Name]')
    original_price = request.form.get('original_price', default=None, type=float)
    sale_price = request.form.get('sale_price', default=None, type=float)
    category = request.form.get('category', default=None)
    info = request.form.get('info', default=None)
    isbn = request.form.get('isbn', default=None)
    pic_file = request.form.get('pic_path', default=None)
    seller_id = 1

    if pic_file is None or pic_file == '':
        pic_file = app.config['NO_PIC_PATH']

    new_book = BookInfo(book_name, original_price, sale_price, category, info, isbn, pic_file, seller_id)
    print(new_book)
    db.session.add(new_book)
    db.session.commit()

    return jsonify({'status': 1, 'msg': 'Success'})


@app.route('/api/buy', methods=['POST'])
@auth.login_required
def buy():
    book_id = request.form.get('book_id')
    target_book = BookInfo.query.filter_by(id=book_id).first()
    if target_book:
        if target_book.bought:
            return jsonify({'status': 0, 'msg': 'Book has already been sold.'})

        buyer_id = g.user.id
        if target_book.seller_id == buyer_id:
            return jsonify({'status': 0, 'msg': 'You cannot buy your own book!.'})

        timestamp = get_timestamp()
        new_order = Order(book_id, buyer_id, timestamp)
        target_book.set_bought(buyer_id)
        db.session.add(new_order)
        db.session.commit()
        return jsonify({'status': 1, 'msg': 'Success'})

    return jsonify({'status': 0, 'msg': 'Book does not exist or other error met.'})


@app.route('/api/detail/<int:book_id>')
def book_info(book_id):
    target_book = BookInfo.query.filter_by(id=book_id).first()
    if target_book:
        return jsonify({'status': 1, 'data': target_book.as_ret_dict(request.url_root)})
    else:
        return jsonify({'status': 0, 'data': None})


@app.route('/api/home/change', methods=['POST'])
@auth.login_required
def change_user_info():
    print(request.form)
    username = request.form.get('username', default=None)
    old_password = request.form.get('old_password', default=None)
    new_password = request.form.get('new_password', default=None)
    email = request.form.get('email', default=None)
    residence = request.form.get('residence[2]', default='')
    delivery = inputs.boolean(request.form.get('delivery', default=None))
    face2face = inputs.boolean(request.form.get('face2face', default=None))
    phone = request.form.get('phone', default=None)

    if g.user.username == username:
        if not g.user.verify_password(old_password):
            return jsonify({'status': 0, 'msg': 'Old password is wrong!'})

        g.user.update(new_password, email, residence, delivery, face2face, phone)
        db.session.add(g.user)
        db.session.commit()
        return jsonify({'status': 1, 'msg': 'Success. You may have to re-login'})
    else:
        return jsonify({'status': 0, 'msg': 'It is not your account!'})


@app.route('/api/want', methods=['POST'])
@auth.login_required
def want():
    # TODO 处理空请求
    book_name = request.form.get('book_name', default='None')
    isbn = request.form.get('isbn', default=None)
    expect_price = request.form.get('expect_price', default=None)
    user_id = g.user.id

    if None in (book_name, isbn, expect_price, user_id):
        return jsonify({'status': 0, 'msg': 'Information incorrect or not full.'})

    new_wantbuy = WantBuy(book_name, expect_price, isbn, user_id)
    db.session.add(new_wantbuy)
    db.session.commit()
    return jsonify({'status': 1, 'msg': 'Success. '})


@app.route('/api/arena')
@auth.login_required
def arena():
    # 排序
    # page_no = request.args.get('page', default=0)
    # item_per_page = request.args.get('items', default=10)
    print(request.args)
    order = request.args.get('order', default='asc')
    key = request.args.get('key', default='discount')
    # 筛选
    category = request.args.get('category', default=None)
    has_pic = inputs.boolean(request.args.get('hasPic', default=False))
    unsold = inputs.boolean(request.args.get('unsold', default=False))
    print(has_pic, unsold)

    all_books = BookInfo.query
    if category is not None:
        print('filter by category')
        all_books = all_books.filter_by(category=category)
    if has_pic:
        print('filter by picture')
        all_books = all_books.filter(BookInfo.picture != app.config['NO_PIC_PATH'])
    if unsold:
        print('filter by whether bought')
        all_books = all_books.filter_by(bought=False)

    key_dict = {
        'price': BookInfo.sale_price,
        'book_name': BookInfo.book_name,
        'discount': BookInfo.discount
    }
    if key in key_dict:
        if order == 'asc':
            print('filter by key asc')
            all_books = all_books.order_by(key_dict[key])
        elif order == 'desc':
            print('filter by key desc')
            all_books = all_books.order_by(desc(key_dict[key]))
        else:
            raise Exception()

    # all_books = all_books.limit(item_per_page).offset(item_per_page * page_no)
    return jsonify([x.as_ret_dict(request.url_root) for x in all_books.all()])


@app.route('/api/message/box')
@auth.login_required
def message_box():
    user_id = g.user.id
    messages = Message.query.filter_by(receiver_id=user_id)
    unread_cnt = len(messages.filter_by(has_read=False).all())
    return jsonify({'data': [x.as_ret_dict() for x in messages.all()], 'unread': unread_cnt})


@app.route('/api/message/send', methods=['POST'])
@auth.login_required
def message_send():
    receiver_name = request.form.get('receiver', default=None)
    sender_id = g.user.id
    content = request.form.get('content', default=None)
    if not content or not receiver_name:
        return jsonify({'status': 0, 'msg': 'Missing information.'})

    receiver = User.query.filter_by(username=receiver_name).first()
    if not receiver:
        return jsonify({'status': 0, 'msg': 'User does not exist.'})
    if receiver.id == sender_id:
        return jsonify({'status': 0, 'msg': 'You cannot send to yourself!'})
    receiver_id = receiver.id
    timestamp = get_timestamp()
    new_message = Message(receiver_id, sender_id, content, timestamp)
    db.session.add(new_message)
    db.session.commit()
    return jsonify({'status': 1, 'msg': 'Success'})


@app.route('/api/home/order')
@auth.login_required
def get_orders():
    sender_id = g.user.id
    buy_orders = BookInfo.query.filter_by(buyer_id=sender_id)
    sell_orders = BookInfo.query.filter_by(seller_id=sender_id)
    ret_d = {'buy': [x.as_ret_dict(request.url_root) for x in buy_orders.all()],
             'sell': [x.as_ret_dict(request.url_root) for x in sell_orders.all()],
             'status': 1
             }
    return jsonify(ret_d)


@app.route('/api/home/want')
@auth.login_required
def get_wantbooks():
    sender_id = g.user.id
    wantbooks = WantBuy.query.filter_by(user_id=sender_id)
    ret_d = {'data': [x.as_ret_dict() for x in wantbooks.all()],
             'status': 1
             }
    return jsonify(ret_d)


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


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']


def get_timestamp():
    return int(datetime.timestamp(datetime.now()))


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/api/home')
@auth.login_required
def home():
    return jsonify(g.user.home_as_dict())


@app.route('/api/message/readall')
@auth.login_required
def readall():
    user_id = g.user.id
    for msg in Message.query.filter_by(receiver_id=user_id).all():
        msg.read()

    db.session.commit()
    return jsonify({'status': 1, 'msg': 'Success'})


@auth.verify_token
def verify_token(token):
    g.user = None
    # first try to authenticate by token
    user = User.verify_auth_token(token)
    if not user:
        return False
    g.user = user
    return True
