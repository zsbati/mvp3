# app.py
from functools import wraps

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
from models import db, User, UserType, TeacherStudent, Comment, Grade
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


    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

teacher_access = db.Table('teacher_access',
                          db.Column('teacher_id', db.Integer, db.ForeignKey('teacher.id'), primary_key=True),
                          db.Column('student_id', db.Integer, db.ForeignKey('student.id'), primary_key=True)
                          )


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Load from the unified User model


@app.route('/')
def index():
    return redirect(url_for('login'))


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


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            print("admin_required: User is not authenticated")  # Add logging
            flash('You must be logged in to access this page.', 'danger')  # More general flash message
            return redirect(url_for('login'))
        elif current_user.user_type != UserType.ADMIN:  # Use elif instead of separate if
            print(
                f"admin_required: User is logged in, but user_type is {current_user.user_type}, not ADMIN")  # Add logging
            flash('You are not authorized to access this page.', 'danger')  # More appropriate flash message
            return redirect(url_for('home'))  # Or another appropriate page
        else:
            print("admin_required: User is an ADMIN. Proceeding to view function.")  # Add logging
        return f(*args, **kwargs)

    return decorated_function


@app.route('/admin')
@login_required
def admin_home():
    print(f"Current user type: {current_user.user_type}")  # Temporary check

    if current_user.user_type != UserType.ADMIN:
        return 'Unauthorized', 403
    users = User.query.order_by(
        User.user_type.asc(),  # Sort by user_type (ADMIN, STUDENT, TEACHER)
        User.username.asc()  # Sort by username alphabetically within each user_type
    ).all()
    return render_template('admin_home.html', users=users)


@app.route('/admin/view_students')
@login_required
@admin_required
def view_students():
    students = User.query.filter_by(user_type=UserType.STUDENT).all()  # Query User, filter by user_type
    return render_template('view_students.html', students=students)


@app.route('/admin/view_teachers')
@login_required
@admin_required
def view_teachers():
    teachers = User.query.filter_by(user_type=UserType.TEACHER).all()  # Query User, filter by user_type
    return render_template('view_teachers.html', teachers=teachers)


@app.route('/admin/home', methods=['GET'])
@login_required
def admin_home_display():
    users = User.query.all()  # Fetch all users to populate the dropdown
    return render_template('admin_home.html', users=users)


@app.route('/admin/change_password', methods=['POST'])
@login_required
def change_user_password():
    if current_user.user_type != UserType.ADMIN:
        flash('Access denied.')
        return redirect(url_for('login'))

    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')

    # Input validation
    if not user_id or not new_password:
        flash('Invalid input.')
        return redirect(url_for('admin_home'))

    user = User.query.filter_by(id=user_id).first()
    if not user:
        flash('User not found.')
        return redirect(url_for('admin_home'))

    # Hash the new password
    hashed_password = generate_password_hash(new_password)
    user.password_hash = hashed_password
    db.session.commit()

    flash(f'Password for {user.username} has been updated successfully.')
    return redirect(url_for('admin_home'))


@app.route('/admin/view_student_page/<int:user_id>')
@login_required
@admin_required
def view_student_page(user_id):
    student = User.query.get_or_404(user_id)
    if student.user_type != UserType.STUDENT:
        flash("User is not a student.", "warning")
        return redirect(url_for('view_students'))

    teacher_comments = Comment.query.filter_by(student_id=student.id).order_by(Comment.timestamp.desc()).all()
    return render_template('student_home.html', student=student, teacher_comments=teacher_comments,
                           admin_view=True)  # Pass admin_view flag


@app.route('/admin/view_teacher_page/<int:user_id>')
@login_required
@admin_required
def view_teacher_page(user_id):
    teacher = User.query.get_or_404(user_id)
    if teacher.user_type != UserType.TEACHER:
        flash("User is not a teacher.", "warning")
        return redirect(url_for('view_teachers'))

    # Fetch the teacher's students using TeacherStudent
    students = User.query.join(TeacherStudent, User.id == TeacherStudent.student_id) \
        .filter(TeacherStudent.teacher_id == teacher.id) \
        .all()

    # Fetch the teacher's comments
    teacher_comments = Comment.query.filter_by(teacher_id=teacher.id).all()

    print(f"Teacher ID: {teacher.id}")
    print(f"Number of students found: {len(students)}")  # Added debug print for students
    print(f"Students data: {students}")  # Added debug print for students
    print(f"Number of comments found: {len(teacher_comments)}")
    print(f"Comments data: {teacher_comments}")

    return render_template('admin_view_teacher.html', teacher=teacher, students=students,
                           teacher_comments=teacher_comments)


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
@admin_required
def create_user():
    if current_user.user_type != UserType.ADMIN:
        return 'Unauthorized', 403

    username = request.form.get('username')
    password = request.form.get('password')
    user_type_str = request.form.get('user_type')

    if not username or not password or not user_type_str:
        flash('All fields are required', 'error')
        return redirect(url_for('admin_home'))

    try:
        user_type = UserType[user_type_str.upper()]  # Ensure case-insensitive matching for enum
    except KeyError:
        flash('Invalid user type', 'error')
        return redirect(url_for('admin_home'))

    # Check if the user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash(f'User {username} already exists', 'error')
        return redirect(url_for('admin_home'))

    # Create and save the new user
    new_user = User(username=username, user_type=user_type)
    new_user.set_password(password)  # Hash the password
    db.session.add(new_user)

    try:
        db.session.commit()
        flash(f'User {username} created successfully', 'success')
    except Exception as e:
        db.session.rollback()  # Rollback in case of any error
        # current_app.logger.error(f"Failed to create user: {e}")
        flash(f'Failed to create user. Please try again. An error occurred: {e}')

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


@app.route('/revoke_access', methods=['POST'])
@login_required
def revoke_access():
    if current_user.user_type != UserType.ADMIN:
        return 'Unauthorized', 403

    teacher_username = request.form['teacher_username']  # changed from teacher to teacher_username
    student_username = request.form['student_username']  # changed from student to student_username

    teacher = User.query.filter_by(username=teacher_username, user_type=UserType.TEACHER).first()
    student = User.query.filter_by(username=student_username, user_type=UserType.STUDENT).first()

    if teacher and student:
        # Find the existing relationship
        existing_access = TeacherStudent.query.filter_by(teacher_id=teacher.id, student_id=student.id).first()
        if existing_access:
            db.session.delete(existing_access)
            db.session.commit()
            flash(f'Access revoked for {teacher_username} from {student_username}')
        else:
            flash(f'No existing access to revoke for {teacher_username} from {student_username}')
    else:
        flash('Invalid teacher or student username')  # Keep error handling consistent

    return redirect(url_for('admin_home'))


@app.route('/revoke_access_form')
@login_required
@admin_required
def revoke_access_form():
    if current_user.user_type != UserType.ADMIN:
        return 'Unauthorized', 403

    teachers = User.query.filter_by(user_type=UserType.TEACHER).all()
    students = User.query.filter_by(user_type=UserType.STUDENT).all()

    return render_template('revoke_access.html', teachers=teachers, students=students)


@app.route('/admin/teachers/<int:teacher_id>')
@login_required
def admin_view_teacher(teacher_id):
    teacher = db.session.get(User, teacher_id)
    if teacher is None:
        return "Teacher not found", 404

    students = User.query.join(TeacherStudent, User.id == TeacherStudent.student_id) \
        .filter(TeacherStudent.teacher_id == teacher_id) \
        .all()

    teacher_comments = Comment.query.filter_by(teacher_id=teacher_id).all()  # Assuming you still want comments

    # Correctly render the template
    return render_template('admin_view_teacher.html', teacher=teacher, students=students,
                           teacher_comments=teacher_comments)


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


@app.route('/my_comments')
@login_required
def my_comments():
    if current_user.user_type != UserType.TEACHER:
        return 'Unauthorized, if you are administrator or inspector, please see the specific students\' page.', 403
    comments = Comment.query.filter_by(teacher_id=current_user.id).all()
    print(comments)
    return render_template('my_comments.html', comments=comments)


@app.route('/add_grade', methods=['POST'])
@login_required
def add_grade():
    if current_user.user_type != UserType.ADMIN:
        flash("You are not authorized to add grades.", "error")
        return redirect(url_for('admin_home'))

    student_id = request.form.get('student_id')
    date = request.form.get('date')
    subject = request.form.get('subject')
    grade = request.form.get('grade')

    # Validate input
    if not all([student_id, date, subject, grade]):
        flash("All fields are required.", "error")
        return redirect(url_for('admin_home'))

    # Verify the selected user is a student
    student = User.query.get(student_id)
    if not student or student.user_type != UserType.STUDENT:
        flash("Invalid student selected.", "error")
        return redirect(url_for('admin_home'))

    # Create new grade
    new_grade = Grade(
        student_id=student_id,
        date=date,
        subject=subject,
        grade=grade
    )
    db.session.add(new_grade)
    db.session.commit()

    flash("Grade added successfully.", "success")
    return redirect(url_for('admin_home'))


if __name__ == '__main__':
    app.run(debug=True)
