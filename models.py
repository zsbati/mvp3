# models.py
from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'student', 'teacher', 'admin'
    comments_received = db.relationship('Comment', backref='student', lazy=True, foreign_keys='Comment.student_id')
    comments_made = db.relationship('Comment', backref='teacher', lazy=True, foreign_keys='Comment.teacher_id')

    accessible_students = db.relationship(
        'User',
        secondary='teacher_access',
        primaryjoin='and_(User.type == "teacher", foreign(User.id) == TeacherAccess.teacher_id)',
        secondaryjoin='and_(User.type == "student", foreign(User.id) == TeacherAccess.student_id)',
        backref=db.backref('accessible_teachers', lazy='dynamic')
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Comment by {self.teacher.username} on {self.timestamp}>'

class TeacherAccess(db.Model):
    __tablename__ = 'teacher_access'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    access_granted = db.Column(db.Boolean, default=True)  # Track if access is granted

    # Define relationships for easier access
    teacher = db.relationship('User', foreign_keys=[teacher_id])
    student = db.relationship('User', foreign_keys=[student_id])

    def __repr__(self):
        return f'<TeacherAccess: {self.teacher.username} -> {self.student.username}, Granted: {self.access_granted}>'
