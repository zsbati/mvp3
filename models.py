# models.py
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import enum

db = SQLAlchemy()


class UserType(enum.Enum):
    ADMIN = 'ADMIN'
    TEACHER = 'TEACHER'
    STUDENT = 'STUDENT'
    INSPECTOR = 'INSPECTOR'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    user_type = db.Column(db.Enum(UserType), nullable=False)  # Using UserType enum for role

    def __init__(self, username, user_type, *args, **kwargs):
        super().__init__(*args, **kwargs)  # Call the parent class constructor
        self.username = username
        self.user_type = user_type

    @property
    def is_authenticated(self):
        return True

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.user_type == UserType.ADMIN

    def is_inspector(self):
        return self.user_type == UserType.INSPECTOR

    def is_teacher(self):
        return self.user_type == UserType.TEACHER

    def is_student(self):
        return self.user_type == UserType.STUDENT

    # Add this method to check if user has edit privileges
    def has_edit_privileges(self):
        return self.user_type == UserType.ADMIN  # Only admins can edit

    # Add this method to check if user has view privileges
    def has_view_privileges(self):
        return self.user_type in [UserType.ADMIN, UserType.INSPECTOR]


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


class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    date = db.Column(db.String(20), nullable=False)  # e.g., "2023-11-15"
    subject = db.Column(db.String(100), nullable=False)
    grade = db.Column(db.String(10), nullable=False)  # e.g., "A", "B+", "90/100"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to the student
    student = db.relationship(
        'User',
        foreign_keys=[student_id],
        backref=db.backref('grades', cascade='all, delete-orphan')
    )
