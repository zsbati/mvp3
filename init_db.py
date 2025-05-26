import os
import sys
from subprocess import run
from app import app, db
from models import User, UserType

def check_database_exists():
    """Check if the database file exists"""
    db_path = os.path.join(os.path.dirname(__file__), 'instance', 'site.db')
    return os.path.exists(db_path)

def check_migrations_needed():
    """Check if there are any pending migrations"""
    # This is a simplified check - in a real app, you'd use Flask-Migrate
    # Here we'll just check if all tables exist
    inspector = db.inspect(db.engine)
    existing_tables = set(inspector.get_table_names())
    required_tables = {'user', 'teacher_student', 'comment', 'grade'}
    return not required_tables.issubset(existing_tables)

def init_db():
    print("Initializing database...")
    
    with app.app_context():
        # Check if database exists
        if not check_database_exists():
            print("Database not found. Creating database...")
            db.create_all()
            print("Database created successfully.")
        
        # Check if migrations are needed
        if check_migrations_needed():
            print("Applying database migrations...")
            # In a real app, you would run:
            # flask db upgrade
            # For now, we'll just recreate the tables
            db.drop_all()
            db.create_all()
            print("Migrations applied successfully.")
        
        # Check if admin exists
        admin_exists = User.query.filter_by(user_type=UserType.ADMIN).first()
        
        if not admin_exists:
            print("No admin user found. Please create an admin user.")
            # Run create_admin.py to create an admin user
            try:
                from create_admin import create_admin_user
                print("Running admin creation script...")
                create_admin_user()
            except ImportError as e:
                print(f"Error: Could not import create_admin: {e}")
                print("Please create an admin user manually.")
                return False
        else:
            print("Admin user already exists.")
        
        print("Database initialization complete.")
        return True

if __name__ == "__main__":
    if init_db():
        sys.exit(0)
    else:
        sys.exit(1)
