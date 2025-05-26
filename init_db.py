import os
import sys
from subprocess import run
from app import app, db
from models import User, UserType

def check_database_exists():
    """Check if the database exists"""
    # For PythonAnywhere, we don't need to check file existence
    # Just check if we can connect to the database
    try:
        db.engine.connect()
        return True
    except:
        return False

def check_migrations_needed():
    """Check if there are any pending migrations"""
    # This is a simplified check - in a real app, you'd use Flask-Migrate
    # Here we'll just check if all tables exist
    inspector = db.inspect(db.engine)
    existing_tables = set(inspector.get_table_names())
    required_tables = {'user', 'teacher_student', 'comment', 'grade'}
    return not required_tables.issubset(existing_tables)

def init_db():

    
    with app.app_context():
        # Check if database exists
        if not check_database_exists():

            db.create_all()

        
        # Check if migrations are needed
        if check_migrations_needed():

            # In a real app, you would run:
            # flask db upgrade
            # For now, we'll just recreate the tables
            db.drop_all()
            db.create_all()

        
        # Check if admin exists
        admin_exists = User.query.filter_by(user_type=UserType.ADMIN).first()
        
        if not admin_exists:

            # Run create_admin.py to create an admin user
            try:
                from create_admin import create_admin_user

                create_admin_user()
            except ImportError as e:
                app.logger.error(f"Error: Could not import create_admin: {e}")

                return False
        else:

        

        return True

if __name__ == "__main__":
    if init_db():
        sys.exit(0)
    else:
        sys.exit(1)
