import sys
import os

UPLOAD_PIC_PATH = './uploads/'
DEBUG = True

WIN = sys.platform.startswith('win')
if WIN:
    prefix = 'sqlite:///'
else:
    prefix = 'sqlite:////'

SQLALCHEMY_DATABASE_URI = prefix + os.path.join('.', 'database/users.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = 'th1s_1s_My_s3creT'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp'}
