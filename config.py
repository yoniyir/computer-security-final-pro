import os

class Config(object):
    basedir = os.path.abspath(os.path.dirname(__file__))
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email configuration
    MAIL_SERVER = 'smtp.example.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'your-email@example.com'
    MAIL_PASSWORD = 'your-email-password'
    MAIL_DEFAULT_SENDER = 'noreply@example.com'

    # Password configuration
    PASSWORD_LENGTH = 10
    PASSWORD_UPPERCASE = True
    PASSWORD_LOWERCASE = True
    PASSWORD_DIGITS = True
    PASSWORD_SPECIAL_CHARS = '!@#$%^&*()_+-='


