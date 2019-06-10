# app/errors.py

from flask import jsonify

# -----------------------------------------------------------------------------
# any custom errors can be put here
# -----------------------------------------------------------------------------

# register global too many requests handler - useful for
# returning json when limit in limiter is reached
def handle_429_request(e):
    return jsonify({ 'message': 'chill out and give it a rest man' }), 429

def handle_wrong_method(e):
    return jsonify({ 'message': 'stop twisting my methods, man' }), 405

def handle_not_found(e):
    return jsonify({ 'message': 'nowt ere for what you want' }), 404
