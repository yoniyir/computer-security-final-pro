import os

class Config(object):
    basedir = os.path.abspath(os.path.dirname(__file__))
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    
    # Flask-Mail configuration
    MAIL_SERVER = 'smtp.zoho.com'
    MAIL_PORT = 465
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_USERNAME = 'rotemmorh@zohomail.com'
    MAIL_PASSWORD = 'Maya2010!'


    # Password configuration
    PASSWORD_LENGTH = 10
    PASSWORD_UPPERCASE = True
    PASSWORD_LOWERCASE = True
    PASSWORD_DIGITS = True
    PASSWORD_SPECIAL_CHARS = '!@#$%^&*()_+-='
    PASSWORD_ATTEMPTS = 3
    COMMON_PASSWORDS = 'common_passwords.csv'


