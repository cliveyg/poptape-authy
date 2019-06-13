# app/services.py
import requests
import json

from flask import current_app as app
import logging

# -----------------------------------------------------------------------------

def call_aws(token, public_id):

    url = app.config['AWS_URL'] 
    headers = { 'Content-type': 'application/json',
                'x-access-token': token }

    data = { 'public_id': public_id }

    try:
        r = requests.post(url, data=json.dumps(data), headers=headers)
    except:
        return False

    if r.status_code == 201:
        return True

    return False


