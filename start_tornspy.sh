#!/bin/bash
python manage.py migrate
python manage.py run_scheduler &
gunicorn tornspy.wsgi
