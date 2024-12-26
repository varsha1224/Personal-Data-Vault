from initdb import db
from datetime import datetime

class User(db.Model):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    hashed_password = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class File(db.Model):
    __tablename__ = 'files'

    file_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_file_path = db.Column(db.String(512), nullable=False)
    encrypted_aes_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Log(db.Model):
    __tablename__ = 'logs'

    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('files.file_id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
