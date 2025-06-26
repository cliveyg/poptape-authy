#!/usr/bin/env bash

source .env

gunicorn -b 0.0.0.0:${PORT} authy:app

#python manage.py runserver_plus 0.0.0.0:${PORT} --cert /tmp/cert
#gunicorn -b 0.0.0.0:9100 -w 1 auctionhouse.wsgi:application
