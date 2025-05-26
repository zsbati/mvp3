# create_db.py
from app import app, db
from models import User, Comment

with app.app_context():
    db.create_all()

app.logger.info("Database tables created successfully!")
