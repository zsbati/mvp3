# create_admin.py
from app import app, db
from models import User
from getpass import getpass

def create_admin():
    with app.app_context():  # Create application context here
        username = input("Enter admin username: ")

        if User.query.filter_by(username=username).first():
            print("Admin user already exists.")
            return

        password = getpass("Enter admin password: ")
        confirm_password = getpass("Confirm admin password: ")

        if password != confirm_password:
            print("Passwords do not match.")
            return

        admin_user = User(username=username, type='admin')
        admin_user.set_password(password)

        db.session.add(admin_user)
        db.session.commit()

        print(f"Admin user '{username}' created successfully.")

if __name__ == "__main__":
    create_admin()
