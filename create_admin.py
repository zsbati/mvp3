# create_admin.py
from app import app, db
from models import User, UserType


def create_admin():
    with app.app_context():
        # Create all tables based on models.py
        db.create_all()

        # Check if an admin user already exists
        admin_user = User.query.filter_by(user_type=UserType.ADMIN).first()
        if admin_user:
            print("An admin user already exists.")
            return

        # Create a new admin user
        username = input("Enter admin username: ")
        password = input("Enter admin password: ")

        new_admin = User(username=username, user_type=UserType.ADMIN)
        new_admin.set_password(password)  # Hash the password
        db.session.add(new_admin)
        db.session.commit()

        print(f"Admin user '{username}' created successfully.")


if __name__ == "__main__":
    create_admin()
