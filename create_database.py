# create_db.py
from app import app, db
from models import User, Comment

with app.app_context():
    db.create_all()

print("Database tables created successfully!")
