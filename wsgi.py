from app import app, db

if __name__ == "__main__":
    # This file is used when running the application with Gunicorn
    # or other WSGI HTTP servers
    app.run()
