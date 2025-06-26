#!/usr/bin/env bash

source .env
gunicorn -b 0.0.0.0:${PORT} authy:app
