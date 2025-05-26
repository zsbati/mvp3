web: gunicorn --worker-tmp-dir /dev/shm --workers=2 --threads=4 --worker-class=gthread --log-file - --access-logfile - --error-logfile - wsgi:app
