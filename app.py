# app.py

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from extensions import db, login_manager
from models import User, Comment, TeacherAccess  # Import models after extensions
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with your secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create the database if it doesn't exist
with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('home'))
        flash('Invalid username or password.')
    return render_template('login.html')


@app.route('/home')
@login_required
def home():
    if current_user.role == 'admin':
        return redirect(url_for('admin_home'))
    elif current_user.role == 'teacher':
        return redirect(url_for('teacher_home'))
    else:
        return redirect(url_for('student_home'))


@app.route('/student_home')
@login_required
def student_home():
    if current_user.role != 'student':
        flash('Access unauthorized.')
        return redirect(url_for('home'))
    return render_template('student_home.html')


@app.route('/teacher_home')
@login_required
def teacher_home():
    if current_user.role != 'teacher':
        flash('Access unauthorized.')
        return redirect(url_for('home'))
    return render_template('teacher_home.html')


@app.route('/teacher/students')
@login_required
def teacher_students():
    if current_user.type != 'teacher':
        flash('Access denied. Only teachers can view this page.', 'danger')
        return redirect(url_for('home'))

    # Get the list of students accessible by the current teacher
    accessible_students = User.query.join(TeacherAccess, User.id == TeacherAccess.student_id).filter(
        TeacherAccess.teacher_id == current_user.id, TeacherAccess.access_granted == True).all()

    return render_template('teacher_students.html', students=accessible_students)


@app.route('/teacher/student/<int:student_id>/comment', methods=['GET', 'POST'])
@login_required
def teacher_comment(student_id):
    if current_user.type != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    student = User.query.get_or_404(student_id)

    # Check if the teacher has access to this student
    access = TeacherAccess.query.filter_by(teacher_id=current_user.id, student_id=student_id,
                                           access_granted=True).first()
    if not access:
        flash('You do not have access to this student.', 'danger')
        return redirect(url_for('teacher_students'))

    if request.method == 'POST':
        comment_text = request.form['comment']
        full_comment = f"{current_user.username}: {comment_text}"  # Prepend username
        new_comment = Comment(student=student, teacher=current_user, comment_text=full_comment)
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully!', 'success')
        return redirect(url_for('teacher_students'))

    return render_template('teacher_comment.html', student=student)


@app.route('/student/comments')
@login_required
def student_comments():
    if current_user.type != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    comments = Comment.query.filter_by(student_id=current_user.id).all()
    return render_template('student_comments.html', comments=comments)


@app.route('/admin_home')
@login_required
def admin_home():
    if current_user.role != 'admin':
        flash('Access unauthorized.')
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin_home.html', users=users)


@app.route('/admin/teacher_access', methods=['GET', 'POST'])
@login_required
def admin_teacher_access():
    if current_user.type != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        teacher_id = request.form['teacher_id']
        student_id = request.form['student_id']
        action = request.form['action']  # 'grant' or 'revoke'

        access = TeacherAccess.query.filter_by(teacher_id=teacher_id, student_id=student_id).first()

        if action == 'grant':
            if access:
                access.access_granted = True
            else:
                new_access = TeacherAccess(teacher_id=teacher_id, student_id=student_id, access_granted=True)
                db.session.add(new_access)
            flash('Access granted!', 'success')
        elif action == 'revoke':
            if access:
                access.access_granted = False  # Set access_granted to False
            # We don't delete the record, to preserve history if needed
            flash('Access revoked!', 'success')

        db.session.commit()
        return redirect(url_for('admin_teacher_access'))

    teachers = User.query.filter_by(type='teacher').all()
    students = User.query.filter_by(type='student').all()
    access_list = TeacherAccess.query.all()

    return render_template('admin_teacher_access.html', teachers=teachers, students=students, access_list=access_list)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_pw = request.form['current_password']
        new_pw = request.form['new_password']
        confirm_pw = request.form['confirm_password']
        if not current_user.check_password(current_pw):
            flash('Current password is incorrect.')
        elif new_pw != confirm_pw:
            flash('New passwords do not match.')
        else:
            current_user.set_password(new_pw)
            db.session.commit()
            flash('Password updated successfully.')
            return redirect(url_for('home'))
    return render_template('change_password.html')


# Admin Routes
@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        flash('Access unauthorized.')
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
        else:
            new_user = User(username=username, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully.')
            return redirect(url_for('admin_home'))
    return render_template('create_user.html')


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access unauthorized.')
        return redirect(url_for('home'))
    user = User.query.get(user_id)
    if user:
        if user.username == current_user.username:
            flash('You cannot delete your own account.')
        else:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully.')
    else:
        flash('User not found.')
    return redirect(url_for('admin_home'))


@app.route('/admin/change_user_password/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_change_user_password(user_id):
    if current_user.role != 'admin':
        flash('Access unauthorized.')
        return redirect(url_for('home'))
    user = User.query.get(user_id)
    if not user:
        flash('User not found.')
        return redirect(url_for('admin_home'))
    if request.method == 'POST':
        new_pw = request.form['new_password']
        confirm_pw = request.form['confirm_password']
        if new_pw != confirm_pw:
            flash('Passwords do not match.')
        else:
            user.set_password(new_pw)
            db.session.commit()
            flash('Password updated successfully.')
            return redirect(url_for('admin_home'))
    return render_template('admin_change_password.html', user=user)


if __name__ == '__main__':
    app.run(debug=True)
