# models.py
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import enum

db = SQLAlchemy()


class UserType(enum.Enum):
    ADMIN = 'admin'
    TEACHER = 'teacher'
    STUDENT = 'student'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    user_type = db.Column(db.Enum(UserType), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class TeacherStudent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    comment = db.Column(db.Text)

    teacher = db.relationship(
        'User',
        foreign_keys=[teacher_id],
        backref=db.backref('students_taught', cascade='all, delete-orphan')
    )
    student = db.relationship(
        'User',
        foreign_keys=[student_id],
        backref=db.backref('teachers', cascade='all, delete-orphan')
    )


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    teacher = db.relationship('User', foreign_keys=[teacher_id])
    student = db.relationship('User', foreign_keys=[student_id])
