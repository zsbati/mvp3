from app import app, db
from models import User, UserType

def add_admin():
    with app.app_context():
        username = input("Enter admin username: ")
        password = input("Enter admin password: ")
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            print(f"User '{username}' already exists!")
            return
            
        # Create new admin user
        admin = User(username=username, user_type=UserType.ADMIN)
        admin.set_password(password)
        
        db.session.add(admin)
        db.session.commit()
        print(f"Admin user '{username}' created successfully!")

if __name__ == "__main__":
    add_admin()
