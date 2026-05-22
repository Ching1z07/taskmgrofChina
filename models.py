from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import check_password_hash as _werkzeug_check
import bcrypt

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id             = db.Column(db.Integer, primary_key=True)
    username       = db.Column(db.String(80), nullable=False, unique=True)
    email          = db.Column(db.String(120), nullable=True, unique=True)
    password_hash  = db.Column(db.String(200), nullable=False)
    is_admin       = db.Column(db.Boolean, default=False)
    reset_code     = db.Column(db.String(6), nullable=True)
    reset_expires  = db.Column(db.DateTime, nullable=True)
    deleted        = db.Column(db.Boolean, default=False)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt(rounds=12)
        ).decode()

    def check_password(self, password):
        h = self.password_hash
        if h.startswith("$2b$") or h.startswith("$2a$"):
            return bcrypt.checkpw(password.encode(), h.encode())
        # köhnə werkzeug hash — yoxla və bcrypt-ə migrasiya et
        if _werkzeug_check(h, password):
            self.set_password(password)
            from models import db
            db.session.commit()
            return True
        return False

class Category(db.Model):
    __tablename__ = "categories"
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(80), nullable=False, unique=True)
    color      = db.Column(db.String(20), default="#3498db")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tasks      = db.relationship("Task", backref="category", lazy=True)

class Message(db.Model):
    __tablename__ = "messages"
    id         = db.Column(db.Integer, primary_key=True)
    sender_id  = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    receiver_id= db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content    = db.Column(db.Text, nullable=False)
    read       = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender     = db.relationship("User", foreign_keys=[sender_id], backref="sent_messages")
    receiver   = db.relationship("User", foreign_keys=[receiver_id], backref="received_messages")

class Task(db.Model):
    __tablename__ = "tasks"
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    status      = db.Column(db.String(20), nullable=False, default="pending")
    priority    = db.Column(db.String(10), default="medium")
    category_id = db.Column(db.Integer, db.ForeignKey("categories.id"), nullable=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    image_path  = db.Column(db.String(255), nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user        = db.relationship("User", backref="tasks", lazy=True)