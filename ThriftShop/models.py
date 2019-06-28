from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from ThriftShop import db
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired, BadSignature


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(128))    # hashed
    residence = db.Column(db.String(255))
    phone_number = db.Column(db.String(30))
    delivery = db.Column(db.Boolean)    # use express delivery or not
    face2face = db.Column(db.Boolean)       # use face2face delivery or not

    def __init__(self, username, email, residence, phone_number):
        self.username = username
        self.email = email
        self.residence = residence
        self.phone_number = phone_number

    def update(self, new_password, email, residence, delivery, face2face, phone):
        if new_password:
            self.set_password(new_password)
        if email:
            self.email = email
        if residence:
            self.residence = residence
        if delivery:
            self.delivery = delivery
        if face2face:
            self.face2face = face2face
        if phone:
            self.phone_number = phone

    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def home_as_dict(self):
        columns = ['id', 'username', 'email', 'residence', 'phone_number', 'use_delivery']
        return {c.name: getattr(self, c.name) for c in self.__table__.columns if c.name in columns}

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
    seller_id = db.Column(db.Integer)
    buyer_id = db.Column(db.Integer)
    bought = db.Column(db.Boolean)

    def __init__(self, book_name, original_price, sale_price, category,
                 info, isbn, picture, seller_id, buyer_id=None, bought=False):
        self.book_name = book_name
        self.original_price = original_price
        self.sale_price = sale_price
        self.discount = sale_price / original_price
        self.category = category
        self.info = info
        self.isbn = isbn
        self.picture = picture
        self.seller_id = seller_id
        self.buyer_id = buyer_id
        self.bought = bought

    def set_bought(self, buyer_id):
        self.bought = True
        self.buyer_id = buyer_id

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def as_ret_dict(self, base_root):
        d = {c.name: getattr(self, c.name) for c in self.__table__.columns}
        d['picture'] = base_root + '/' + d['picture']
        d['seller_id'] = User.query.filter_by(id=d['seller_id']).first().username
        return d

    def __repr__(self):
        return str(self.as_dict())


class WantBuy(db.Model):
    __tablename__ = 'wantlist'
    # book info
    id = db.Column(db.Integer, primary_key=True)
    book_name = db.Column(db.String(80))
    expect_price = db.Column(db.Float)
    isbn = db.Column(db.String(30))
    user_id = db.Column(db.Integer)

    def __init__(self, book_name, expect_price, isbn, user_id):
        self.book_name = book_name
        self.expect_price = expect_price
        self.isbn = isbn
        self.user_id = user_id

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def as_ret_dict(self):
        return self.as_dict()


    def __repr__(self):
        return str(self.as_dict())


class Order(db.Model):
    __tablename__ = 'orders'
    # book info
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer)
    buyer_id = db.Column(db.Integer)
    timestamp = db.Column(db.BigInteger)

    def __init__(self, book_id, buyer_id, timestamp):
        self.book_id = book_id
        self.buyer_id = buyer_id
        self.timestamp = timestamp

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def __repr__(self):
        return str(self.as_dict())


class Message(db.Model):
    __tablename__ = 'messages'
    # book info
    id = db.Column(db.Integer, primary_key=True)
    receiver_id = db.Column(db.Integer)
    sender_id = db.Column(db.Integer)
    content = db.Column(db.Text)
    timestamp = db.Column(db.BigInteger)
    has_read = db.Column(db.Boolean)

    def __init__(self, receiver_id, sender_id, content, timestamp, has_read=False):
        self.receiver_id = receiver_id
        self.sender_id = sender_id
        self.content = content
        self.timestamp = timestamp
        self.has_read = has_read

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def as_ret_dict(self):
        d = self.as_dict()
        d['sender_name'] = User.query.filter_by(id=self.sender_id).first().username
        return d

    def read(self):
        self.has_read = True

    def __repr__(self):
        return str(self.as_dict())
