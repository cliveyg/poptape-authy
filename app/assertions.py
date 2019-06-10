import os.path
import json
from jsonschema import validate, draft7_format_checker
from jsonschema.exceptions import ValidationError as JsonValidationError

from flask import current_app as app
import logging

def assert_valid_schema(data, schema_type):
    # checks whether the given data matches the schema

    #TODO: validate on a particular country's address schema based on input iso_code
    #TODO: get these from redis or similar - only get from disk first time

    if schema_type == 'login':
        schema = _load_json_schema('schemas/login.json')
    elif schema_type == 'create_user':
        schema = _load_json_schema('schemas/user_schema.json')
    elif schema_type == 'role':
        schema = _load_json_schema('schemas/role_schema.json')    

    return validate(data, schema, format_checker=draft7_format_checker)

# -----------------------------------------------------------------------------

def _load_json_schema(filename):
    # loads the given schema file
    filepath = os.path.join(os.path.dirname(__file__), filename)

    with open(filepath) as schema_file:
        return json.loads(schema_file.read())
