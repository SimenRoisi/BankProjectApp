from . import db
import base64
import os
from flask_login import UserMixin
from sqlalchemy.sql import func
import onetimepass
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, EqualTo
from flask_login import UserMixin
from sqlalchemy.orm import backref
from sqlalchemy.sql import func
import uuid
from flask import flash
from datetime import datetime, timedelta

#from BankProsjekt.website.auth import transaction
from . import db
from . import Bcrypt
from otpauth import OtpAuth as path

bcrypt = Bcrypt()


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10000), nullable=False)
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email_address = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    notes = db.relationship('Note', backref="owned_user", lazy=True)
    accounts = db.relationship("Account", backref="owned user", lazy=True)
    transactions = db.relationship("Transaction", lazy=True)
    otp_secret = db.Column(db.String(16))
    salt_value = db.Column(db.String())
    failed_logins = db.Column(db.Integer(), nullable=True)
    block_login_timestamp = db.Column(db.DateTime(timezone=True), default=None ,nullable=True)
    login_timestamp = db.Column(db.DateTime(timezone=True), default=None ,nullable=True)
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')


    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
            .format(self.email_address, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    def check_login_time(self, time):
        return time < self.login_timestamp + timedelta(minutes=30)

    @property
    def password(self):
        return self.password_hash

    @password.setter
    def password(self, plain_text_password):
        self.salt_value = str(uuid.uuid4())
        self.password_hash = bcrypt.generate_password_hash(plain_text_password + self.salt_value).decode('utf-8')

    def check_password_correction(self, attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password + self.salt_value)


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    account_name = db.Column(db.String(60))
    account_balance = db.Column(db.Integer)
    account_number = db.Column(db.String(120), unique=True)
    account_description = db.Column(db.String(160))


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id_out = db.Column(db.Integer, db.ForeignKey("user.id"))
    user_id_in = db.Column(db.Integer)
    trans_amount =db.Column(db.Integer)
    account_in_number = db.Column(db.String(120))
    account_in_name = db.Column(db.String(60))
    account_out_number = db.Column(db.String(120))
    account_out_name = db.Column(db.String(60))
    trans_msg = db.Column(db.String(120))




