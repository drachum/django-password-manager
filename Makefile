#!/bin/bash
npm run build
python manage.py collectstatic
echo "yes"
python manage.py runserver
