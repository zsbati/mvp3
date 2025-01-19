# create_admin.py
from models import db, User
from app import app
from getpass import getpass

def create_admin():
    with app.app_context():
        db.create_all()
        username = input('Enter admin username: ')
        if User.query.filter_by(username=username).first():
            print('Username already exists.')
            return
        password = getpass('Enter admin password: ')
        confirm_password = getpass('Confirm admin password: ')
        if password != confirm_password:
            print('Passwords do not match.')
            return
        admin = User(username=username, role='admin')
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print('Administrator account created successfully.')

if __name__ == '__main__':
    create_admin()
