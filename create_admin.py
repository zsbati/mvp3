#!/usr/bin/env python3
"""
Admin user creation utility for the application.
Run this script directly to create an admin user interactively,
or import the create_admin_user function to use it programmatically.
"""
import getpass
from app import app, db
from models import User, UserType
from werkzeug.security import generate_password_hash

def create_admin_user(username=None, password=None, interactive=True):
    """
    Create an admin user.
    
    Args:
        username (str, optional): Username for the admin. If None, will prompt.
        password (str, optional): Password for the admin. If None, will prompt.
        interactive (bool): Whether to prompt for missing information.
    
    Returns:
        bool: True if user was created, False otherwise
    """
    with app.app_context():
        # Check if user already exists
        if username and User.query.filter_by(username=username).first():
            print(f"Error: User '{username}' already exists!")
            return False
            
        # Get username if not provided
        if not username and interactive:
            while True:
                username = input("Enter admin username: ").strip()
                if not username:
                    print("Username cannot be empty!")
                    continue
                if User.query.filter_by(username=username).first():
                    print(f"User '{username}' already exists!")
                    continue
                break
        
        # Get password if not provided
        if not password and interactive:
            while True:
                password = getpass.getpass("Enter admin password: ").strip()
                if not password:
                    print("Password cannot be empty!")
                    continue
                password_confirm = getpass.getpass("Confirm password: ").strip()
                if password != password_confirm:
                    print("Passwords do not match!")
                    continue
                break
        
        # Validate we have what we need
        if not username or not password:
            print("Error: Username and password are required!")
            return False
        
        try:
            # Create admin user
            admin = User(
                username=username,
                user_type=UserType.ADMIN
            )
            admin.set_password(password)
            
            db.session.add(admin)
            db.session.commit()
            
            if interactive:
                print(f"\nAdmin user '{username}' created successfully!")
                print("IMPORTANT: Keep these credentials secure!")
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"Error creating admin user: {e}")
            return False

if __name__ == "__main__":
    import sys
    
    # Allow passing username/password as command line arguments
    username = sys.argv[1] if len(sys.argv) > 1 else None
    password = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Run interactively if no args provided
    if not username or not password:
        print("=== Create Admin User ===")
    
    success = create_admin_user(username, password)
    sys.exit(0 if success else 1)
