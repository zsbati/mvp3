# create_admin.py
from app import app, db
from models import User, UserType  # Modified import - using unified User model
from werkzeug.security import generate_password_hash


def create_admin_user(username, password):
    with app.app_context():
        existing_admin = User.query.filter_by(username=username, user_type=UserType.ADMIN).first()
        if existing_admin:
            print(f"Admin user '{username}' already exists.")
            return

        hashed_password = generate_password_hash(password)
        admin_user = User(username=username, password_hash=hashed_password,
                          user_type=UserType.ADMIN)  # Create User with user_type
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user '{username}' created successfully.")


if __name__ == '__main__':
    admin_username = "admin"
    admin_password = "password"
    create_admin_user(admin_username, admin_password)
