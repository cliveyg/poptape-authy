# app/services.py
import requests

# -----------------------------------------------------------------------------

def call_requests(url, headers):
    r = requests.get(url, headers=headers)
    return r


