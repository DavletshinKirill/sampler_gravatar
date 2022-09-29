from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
import hashlib


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_name = db.Column(db.String(70), unique=True)
    password = db.Column(db.Text)
    # about_me = db.Column(db.String(140))
    # last_seen = db.Column(db.DateTime)

    def __init__(self, name, password):
        self.user_name = name
        self.hash_password(password)

    def __repr__(self):
        return '<User %r>' % self.id

    def hash_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def gravatar(self, size=100, default='identicon', rating='g'):
        url = 'https://secure.gravatar.com/avatar'
        hash = hashlib.md5(self.user_name.lower().encode('utf-8')).hexdigest()
        print('{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating))
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

