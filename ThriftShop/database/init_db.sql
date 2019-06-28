PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (
	id INTEGER NOT NULL,
	username VARCHAR(80),
	email VARCHAR(255),
	password VARCHAR(128),
	residence VARCHAR(255),
	phone_number VARCHAR(30),
	delivery BOOLEAN,
	face2face BOOLEAN,
	PRIMARY KEY (id),
	UNIQUE (username),
	UNIQUE (email),
	CHECK (delivery IN (0, 1)),
	CHECK (face2face IN (0, 1))
);
INSERT INTO users VALUES(1,'administrator','1176827825@qq.com','pbkdf2:sha256:50000$GkbZmLHG$f9c2e34058cbbd20236e9529b5d355a802033ce1b71dceb5f5ca80e661405486','zijingang','13123600300',NULL,NULL);
INSERT INTO users VALUES(2,'normaluser','normal@normal.user','pbkdf2:sha256:50000$lvgfNalx$5d7c8208759baacf9beeae7cb5d2141b761d274c672da12e7ab9fe7c50bdda26','yuquan','13306519390',NULL,NULL);
CREATE TABLE book_info (
	id INTEGER NOT NULL,
	book_name VARCHAR(80),
	original_price FLOAT,
	sale_price FLOAT,
	discount FLOAT,
	category VARCHAR(30),
	info TEXT,
	isbn VARCHAR(30),
	picture VARCHAR(100),
	seller_id INTEGER,
	buyer_id INTEGER,
	bought BOOLEAN,
	PRIMARY KEY (id),
	CHECK (bought IN (0, 1))
);
INSERT INTO book_info VALUES(1,'三体',100.0,30.0,0.3,'sci-fi',NULL,'9787536692930','/static/uploads/139e53_9787536692930_.jpg',1,NULL,0);
INSERT INTO book_info VALUES(2,'五年高考三年模拟',100.0,18.0,0.17999999999999996447,'textbook',NULL,'9787504183040','/static/uploads/139e71_9787504183040_.jpg',1,NULL,0);
INSERT INTO book_info VALUES(3,'三国演义',200.0,30.0,0.15,'history',NULL,'9787020008728','/static/uploads/139e89_9787020008728_.jpg',1,NULL,0);
INSERT INTO book_info VALUES(4,'活着',80.0,75.0,0.9375,'classic',NULL,'9787506365437','/static/uploads/139e9e_9787506365437_.jpg',1,NULL,0);
INSERT INTO book_info VALUES(5,'我在故宫修文物',75.0,20.0,0.26666666666666665186,'culture',NULL,'9787549590353','/static/uploads/139eb8_9787549590353_.jpg',1,NULL,0);
INSERT INTO book_info VALUES(6,'飘',187.99999999999998934,77.999999999999998223,0.41489361702127656172,'love',NULL,'9787806570920','/static/uploads/139eca_9787806570920_.jpg',1,NULL,0);
INSERT INTO book_info VALUES(7,'红楼梦',300.0,239.99999999999999111,0.8,'classic',NULL,'9787020002207','/static/uploads/139f8d_9787020002207_.jpg',1,NULL,0);
INSERT INTO book_info VALUES(8, '水浒传',85.0,30.0,0.35294117647058826925,'classic',NULL,'9787535391841','/static/no_pic.jpg',1,NULL,0);
CREATE TABLE wantlist (
	id INTEGER NOT NULL,
	book_name VARCHAR(80),
	expect_price FLOAT,
	isbn VARCHAR(30),
	user_id INTEGER,
	PRIMARY KEY (id)
);
CREATE TABLE orders (
	id INTEGER NOT NULL,
	book_id INTEGER,
	buyer_id INTEGER,
	timestamp BIGINT,
	PRIMARY KEY (id)
);
CREATE TABLE messages (
	id INTEGER NOT NULL,
	receiver_id INTEGER,
	sender_id INTEGER,
	content TEXT,
	timestamp BIGINT,
	has_read BOOLEAN,
	PRIMARY KEY (id),
	CHECK (has_read IN (0, 1))
);
COMMIT;
