# app.py
from sqlalchemy import event, text
from sqlalchemy.engine import Engine

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)
from models import db, User, UserType, TeacherStudent, Comment
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db.init_app(app)

# Enable foreign key constraints for SQLite using event listener
with app.app_context():
    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        if app.config['SQLALCHEMY_DATABASE_URI'].startswith("sqlite"):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.close()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_type_str = request.form['user_type']
        user_type = UserType(user_type_str)

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
            return redirect(url_for('register'))

        new_user = User(username=username, user_type=user_type)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful, please log in')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            if user.user_type == UserType.ADMIN:
                return redirect(url_for('admin_home'))
            elif user.user_type == UserType.TEACHER:
                return redirect(url_for('teacher_home'))
            elif user.user_type == UserType.STUDENT:
                return redirect(url_for('student_home'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']

        if current_user.check_password(old_password):
            current_user.set_password(new_password)
            db.session.commit()
            flash('Password changed successfully')
            return redirect(url_for('change_password'))
        else:
            flash('Invalid old password')

    return render_template('change_password.html')


@app.route('/admin')
@login_required
def admin_home():
    if current_user.user_type != UserType.ADMIN:
        return 'Unauthorized', 403
    users = User.query.all()
    return render_template('admin_home.html', users=users)


@app.route('/teacher')
@login_required
def teacher_home():
    if current_user.user_type != UserType.TEACHER:
        return 'Unauthorized', 403

    teacher_students = TeacherStudent.query.filter_by(teacher_id=current_user.id).all()
    students = [ts.student for ts in teacher_students]

    return render_template('teacher_home.html', students=students)


@app.route('/student')
@login_required
def student_home():
    if current_user.user_type != UserType.STUDENT:
        return 'Unauthorized', 403

    # Grab all comments for this student from the Comment table
    teacher_comments = Comment.query.filter_by(student_id=current_user.id).order_by(Comment.timestamp.desc()).all()

    return render_template('student_home.html', teacher_comments=teacher_comments)


@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    if current_user.user_type != UserType.ADMIN:
        return 'Unauthorized', 403

    username = request.form['username']
    password = request.form['password']
    user_type_str = request.form['user_type']
    user_type = UserType(user_type_str)

    new_user = User(username=username, user_type=user_type)
    new_user.set_password(password)  # Hash the password
    db.session.add(new_user)
    db.session.commit()

    flash(f'User {username} created successfully')
    return redirect(url_for('admin_home'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.user_type != UserType.ADMIN:
        return 'Unauthorized', 403

    user = User.query.get_or_404(user_id)

    try:
        # Deleting associated TeacherStudent and Comment records is handled by cascade
        db.session.delete(user)
        db.session.commit()

        flash(f'User {user.username} deleted successfully')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}')
        return redirect(url_for('admin_home')), 500

    return redirect(url_for('admin_home'))


@app.route('/grant_access', methods=['POST'])
@login_required
def grant_access():
    if current_user.user_type != UserType.ADMIN:
        return 'Unauthorized', 403

    teacher_username = request.form['teacher_username']
    student_username = request.form['student_username']

    teacher = User.query.filter_by(username=teacher_username, user_type=UserType.TEACHER).first()
    student = User.query.filter_by(username=student_username, user_type=UserType.STUDENT).first()

    if teacher and student:
        # Check if the relationship already exists
        existing_access = TeacherStudent.query.filter_by(teacher_id=teacher.id, student_id=student.id).first()
        if not existing_access:
            teacher_student = TeacherStudent(teacher_id=teacher.id, student_id=student.id)
            db.session.add(teacher_student)
            db.session.commit()
            flash(f'Access granted for {teacher_username} to {student_username}')
        else:
            flash(f'Access already granted for {teacher_username} to {student_username}')
    else:
        flash('Invalid teacher or student username')

    return redirect(url_for('admin_home'))


@app.route('/add_comment/<int:student_id>', methods=['POST'])
@login_required
def add_comment(student_id):
    if current_user.user_type != UserType.TEACHER:
        return 'Unauthorized', 403

    new_comment_text = request.form['comment']

    # Verify the teacher has access to this student
    teacher_student = TeacherStudent.query.filter_by(
        teacher_id=current_user.id,
        student_id=student_id
    ).first()

    if teacher_student:
        # Create a new Comment row
        new_comment = Comment(
            teacher_id=current_user.id,
            student_id=student_id,
            content=new_comment_text
        )
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully')
    else:
        flash('You do not have access to this student')

    return redirect(url_for('teacher_home'))


if __name__ == '__main__':
    app.run(debug=True)
