from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, Regexp
from app.models import User
import re
from flask import current_app as app


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')
    
    # Validate password from the config file
    def validate_password(self, password):
        config = app.config

        if len(password.data) < config['PASSWORD_LENGTH']:
            raise ValidationError(f'Password must be at least {config["PASSWORD_LENGTH"]} characters long.')

        if config['PASSWORD_UPPERCASE'] and not re.search('[A-Z]', password.data):
            raise ValidationError('Password must contain at least one uppercase letter.')

        if config['PASSWORD_LOWERCASE'] and not re.search('[a-z]', password.data):
            raise ValidationError('Password must contain at least one lowercase letter.')

        if config['PASSWORD_DIGITS'] and not re.search('[0-9]', password.data):
            raise ValidationError('Password must contain at least one digit.')

        if config['PASSWORD_SPECIAL_CHARS'] and not re.search('[\W_]', password.data):
            special_chars = config['PASSWORD_SPECIAL_CHARS']
            raise ValidationError(f'Password must contain at least one special character from: {special_chars}')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=10),
        Regexp('(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_])', message="Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')
