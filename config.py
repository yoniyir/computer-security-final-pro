import os

class Config(object):
    basedir = os.path.abspath(os.path.dirname(__file__))
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email configuration
    
    # Flask-Mail configuration
    MAIL_SERVER = 'smtp.mail.yahoo.com'
    MAIL_PORT = 465
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_USERNAME = 'zlray@yahoo.com'
    MAIL_PASSWORD = 'zuvr123456789'


    # Password configuration
    PASSWORD_LENGTH = 10
    PASSWORD_UPPERCASE = True
    PASSWORD_LOWERCASE = True
    PASSWORD_DIGITS = True
    PASSWORD_SPECIAL_CHARS = '!@#$%^&*()_+-='


