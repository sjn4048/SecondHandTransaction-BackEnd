from flask_login import UserMixin
from flask import jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from ThriftShop import db
from sqlalchemy.orm import relationship
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired, BadSignature


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(128))    # hashed
    residence = db.Column(db.String(255))
    phone_number = db.Column(db.String(30))
    # Books
    posted_books = relationship('BookInfo')
    #bought_books = relationship('BookInfo')
    # Other info
    use_delivery = db.Column(db.Boolean)    # use express delivery or not

    def __init__(self, username, email, residence, phone_number):
        self.username = username
        self.email = email
        self.residence = residence
        self.phone_number = phone_number

    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def generate_token(self, expiration=60*60*24*10):
        # 默认token时长：10天
        from ThriftShop import app
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        from ThriftShop import app
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = User.query.get(data['id'])
        return user


class BookInfo(db.Model):
    __tablename__ = 'book_info'
    # book info
    id = db.Column(db.Integer, primary_key=True)
    book_name = db.Column(db.String(80))
    original_price = db.Column(db.Float)
    sale_price = db.Column(db.Float)
    discount = db.Column(db.Float)
    category = db.Column(db.String(30))
    info = db.Column(db.Text())
    isbn = db.Column(db.String(30))
    picture = db.Column(db.String(100))    # file path
    # user info
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # buyer_id = db.Column(db.Integer)

    def __init__(self, book_name, original_price, sale_price, category,
                 info, isbn, picture, seller_id):
        self.book_name = book_name
        self.original_price = original_price
        self.sale_price = sale_price
        self.discount = sale_price / original_price
        self.category = category
        self.info = info
        self.isbn = isbn
        self.picture = picture
        self.seller_id = seller_id

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def __repr__(self):
        return jsonify(self.as_dict())


