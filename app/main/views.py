from app import db, limiter
#from login.aws import create_aws_user
from app.models import User, Role, UserRole 
from app.assertions import assert_valid_schema
from app.main import bp
from flask import current_app as app

from flask import jsonify, request, make_response, abort, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from functools import wraps

import uuid
import jwt
import datetime
import time
import pprint
import json
import logging

from urllib.parse import unquote
from sqlalchemy.exc import SQLAlchemyError, DBAPIError
from psycopg2.errors import UniqueViolation
from sqlalchemy import func, and_ 
from jsonschema.exceptions import ValidationError as JsonValidationError

# this is a password checker from dropbox
from zxcvbn import zxcvbn

# reject any non-json requests
@bp.before_request
def only_json():
    if not request.is_json:
        return jsonify({ 'message': 'Input must be json'}), 400

#-----------------------------------------------------------------------------#
# wrapper function to check if token is supplied to routes
#-----------------------------------------------------------------------------#

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if app.config['ENVIRONMENT'] == 'PRODUCTION' and not request.is_secure:
            return jsonify({ 'message': 'La la la, I\'m not listening. All requests must be over https not http.'}), 400

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({ 'message': 'Token not supplied.'}), 401
          
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS512')
            
            # get the lowest access level for the current user
            result = db.session.query(User.username,User.public_id,Role.name,Role.level).filter(User.id == UserRole.user_id).filter(UserRole.role_id == Role.id).filter(User.public_id == data['public_id']).order_by(Role.level).all()
            current_user = result[0]

        except (SQLAlchemyError, jwt.InvalidTokenError, DBAPIError) as e:
            return jsonify({ 'message': 'Invalid token.'}), 401

        if not current_user:
            return jsonify({ 'message': 'Invalid token.'}), 401

        # deal with near expired token here
        #if near_expiry(data['exp']):
            #print('near expiry.')
            #new_token = jwt.encode({ 'public_id': current_user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30) }, app.config['SECRET_KEY'])
            #kwargs = { 'token': new_token.decode('UTF-8') }

        return f(current_user, *args, **kwargs)

    return decorated

#-----------------------------------------------------------------------------#
# wrapper function to check access level for user
#-----------------------------------------------------------------------------#

def require_access_level(access_level):
    def actual_decorator(f):
        @wraps(f)
        def decorated(current_user, *args, **kwargs):

            if current_user.level > access_level:
                return jsonify({ 'message': 'Severe tutting ensues.'}), 401 

            return f(current_user, *args, **kwargs)

        return decorated
    return actual_decorator


#------------------------------------------------------------------------------#

#TODO: MAYBE WE SHOULD CHECK URL THE REQUEST COMES FROM TO PREVENT CROSS SITE STUFF
@bp.route('/authy/checkaccess/<external_level>', methods=['GET'])
@token_required
@require_access_level(10)
def check_access_level(current_user, external_level):

    url_string = app.config['BASE_URLS']
    good_urls = url_string.split(",")

    if request.host in good_urls:    

        numeric_level = 999
        try:
            numeric_level = int(external_level)
        except:
            return jsonify({ 'message': 'Your name\'s not down, you\'re not coming in.'}), 401

        if current_user.level <= numeric_level: 
            return jsonify({ 'public_id': current_user.public_id }), 200

    return jsonify({ 'message': 'Your name\'s not down, you\'re not coming in.'}), 401

#------------------------------------------------------------------------------#

@bp.route('/authy/validate/<user_id>', methods=['GET'])
@token_required
@require_access_level(10)
def check_jwt_against_user_id(current_user, user_id):

    if current_user.public_id == user_id:
        return jsonify({ 'message': 'On the guest list'}), 200

    return jsonify({ 'message': 'Your name\'s not down, you\'re not coming in.'}), 401
    

#-----------------------------------------------------------------------------#
# user routes
#-----------------------------------------------------------------------------#

# log user in
@bp.route('/authy/login', methods=['POST'])
@limiter.limit("10/hour")
def login_user():

    # check input is valid json
    app.logger.debug(request.get_json())
    try:
        login_data = request.get_json()
    except:
        return jsonify({ 'message': 'Check ya inputs mate. Yer not valid, Jason'}), 400

    #TODO: Change is_secure to X-FORWARDED-PROTO as we use nginx as proxy
    if app.config['ENVIRONMENT'] == 'PRODUCTION' and not request.is_secure:
        return jsonify({ 'message': 'La la la, I\'m not listening. All requests must be over https not http.'}), 400
    
    #TODO: Changing from HTTP Basic Auth to form based due to utf8 constraints in Basic Auth
    # validate input against json schemas
    try:
        assert_valid_schema(login_data, 'login')
    except JsonValidationError as error:
        app.logger.debug("The error is [%s]", str(error))
        return jsonify({ 'message': 'Check ya inputs mate.'}), 400

    #TODO: refactor this - could do a lot of checks in the model query
    try:
        user = User.query.filter_by(username = login_data.get('username')).first()
    except: # pragma: no cover
        return jsonify({ 'message': 'Could not verify user'}), 401 # pragma: no cover

    # can't let 'deleted' user login
    if not user or user.deleted == True:
        return jsonify({ 'message': 'Could not verify this user'}), 401

    # user exists so check password
    if check_password_hash(user.password, login_data.get('password')):
        token = jwt.encode({ 'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=240) }, 
                           app.config['SECRET_KEY'],
                           algorithm='HS512')

        # update last_login field
        user.last_login = datetime.datetime.utcnow()
        try:
            db.session.commit()
            # return the token to client
            return jsonify({ 'token': token.decode('UTF-8') })
        except: # pragma: no cover
            db.session.rollback() # pragma: no cover
            return jsonify({ 'message': 'Oopsy something went wrong, try again' }), 500 # pragma: no cover

    return jsonify({ 'message': 'Could not verify user identity'}), 401


#------------------------------------------------------------------------------#


@bp.route('/authy/user', methods=['GET'])
@token_required
@require_access_level(10)
def get_current_user_details(current_user):

    user = User.query.filter_by(public_id = current_user.public_id).first()
    
    if not user:
        return jsonify({ 'message': 'hmmm, you\'re not in our records' }), 404

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['username'] = user.username
    user_data['email'] = user.email
    user_data['created'] = user.created
    user_data['last_login'] = user.last_login

    return jsonify(user_data), 200

#------------------------------------------------------------------------------#


@bp.route('/authy/users', methods=['GET'])
@token_required
@require_access_level(5)
def get_all_users(current_user):

    # pagination allowed on this url
    page = request.args.get('page', 1, type=int)
    total_records = 0
    users_per_page = int(app.config['USERS_LIMIT_PER_PAGE'])

    try:
        total_records = db.session.query(User).count()
        users = db.session.query(User).paginate(page, users_per_page, False).items
    except:
        return jsonify({ 'message': 'oopsy, sorry we couldn\'t complete your request' }), 500

    if len(users) == 0:
        return jsonify({ 'message': 'no users found in system!' }), 404

    paged_users = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['email'] = user.email
        user_data['created'] = user.created
        user_data['last_login'] = user.last_login
        user_data['deleted'] = user.deleted
        user_data['delete_date'] = user.delete_date
        paged_users.append(user_data)

    output = { 'users': paged_users }
    output['total_records'] = total_records
    total_so_far = page * users_per_page

    if total_so_far < total_records:
        npage = page + 1
        output['next_url'] = '/authy/users?page='+str(npage)

    if page > 1:
        ppage = page - 1
        output['prev_url'] = '/authy/users?page='+str(ppage)

    return jsonify(output), 200

#------------------------------------------------------------------------------#


@bp.route('/authy/user/<public_id>', methods=['GET'])
@token_required
@require_access_level(5)
def get_one_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user or user.deleted:
        return jsonify({ 'message': 'User not found for id ['+public_id+']' }), 404

    user_data = {}
    user_data['username'] = user.username
    user_data['email'] = user.email
    user_data['created'] = user.created
    user_data['last_login'] = user.last_login
    user_data['deleted'] = user.deleted
    user_data['delete_date'] = user.delete_date

    return jsonify(user_data)


#------------------------------------------------------------------------------#

@bp.route('/authy/user', methods=['POST'])
@limiter.limit("10/hour")
#@token_required
#@require_access_level(5)
#def create_user(current_user):
def create_user():

    try:
        data = request.get_json()
    except:
        return jsonify({ 'message': 'Check ya inputs mate. Yer not valid, Jason'}), 400

    try:
        assert_valid_schema(data, 'create_user')
    except JsonValidationError as err:
        mess = err.message
        if "does not match '[A-Z" in mess:
            mess = "Email address is not valid"

        return jsonify({ 'message': 'Check ya inputs mate.', 'error': mess }), 400

    if data['password'] != data['confirm_password']:
        return jsonify({ 'message': 'Passwords don\'t match'}), 400

    # password strength checking - not sure what value to accept
    results = zxcvbn(data['password'], user_inputs=[data['email'], data['username']])

    passfail = False
    if 'passfail' in data:
        passfail = True

    # return if password is too weak
    if ((app.config['ENVIRONMENT'] == 'PRODUCTION' and results.get('score') < 3) or
        (app.config['ENVIRONMENT'] == 'TEST' and results.get('score') < 3) or
        (app.config['ENVIRONMENT'] == 'DEVELOPMENT' and passfail)):

        new_dict = {}
        new_dict['message'] = "Sorry your password is too weak, please try another"
        new_dict['guesses'] = results['guesses']
        new_dict['feedback'] = results['feedback']
        new_dict['score'] = results['score']
        return jsonify(new_dict), 401

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha512')
    ts = time.time()
    datetime_string = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    # get a unique id for public_id and fill rest of user record
    new_user = User(public_id = str(uuid.uuid4()),
                    username = data['username'],
                    password = hashed_password,
                    created  = datetime_string,
                    last_login = datetime_string,
                    email = data['email']) 

    try:
        db.session.add(new_user)
        db.session.flush()
        db.session.commit()
    except (SQLAlchemyError, DBAPIError, UniqueViolation) as e:
        db.session.rollback()
        app.logger.debug(str(e))
        if "duplicate" in str(e):
            error_message = 'Your username and/or email is already registered with us'
            return jsonify({ 'message': 'Oopsy, something went wrong.' , 'error': error_message }), 409
        else:
            error_message = 'We were unable to create your user profile'
            return jsonify({ 'message': 'Oopsy, something went wrong.' , 'error': error_message }), 500 

    # assign 'user' role to new user
    role = Role.query.filter_by(name="user").first()
    user_role = UserRole(user_id = new_user.id,
                         role_id = role.id)

    try:
        db.session.add(user_role)
        db.session.commit()
    except (SQLAlchemyError, DBAPIError) as e: # pragma: no cover
        db.session.rollback() # pragma: no cover
        return jsonify({ 'message': 'Oopsy, something went wrong.'}), 500 # pragma: no cover

    return jsonify({ 'message': 'Success! User ['+data['username']+'] created.'}), 201
    #if create_aws_user(new_user.public_id,new_user.id):
    #    return jsonify({ 'message': 'Success! User ['+data['username']+'] created.'}), 201
    #db.session.rollback() 
    #return jsonify({ 'message': 'Oopsy, something went a bit wrong.'}), 500


#------------------------------------------------------------------------------#

#TODO: if changing password need two password fields
# and need to check various combinations 
@bp.route('/authy/user/<public_id>', methods=['PUT'])
@token_required
@require_access_level(5)
def edit_user(current_user, public_id):

    #user = User.query.filter_by(public_id=public_id).first()

    #if not user:
    #    return jsonify({ 'message': 'User not found for id ['+public_id+']' }), 404

    return jsonify({ 'message': 'Like those Levis' }), 501

#------------------------------------------------------------------------------#

@bp.route('/authy/user/<public_id>', methods=['DELETE'])
@token_required
@require_access_level(5)
def admin_delete_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    ts = time.time()
    datetime_string = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    if not user:
        return jsonify({ 'message': 'User not found for id ['+public_id+']' }), 404

    # if user exists but the delete flag is set ie; previously deleted then return a 410 no content
    #TODO: Maybe switch this to a 404?
    if user.deleted == True:
        return jsonify({ 'message': 'User ['+public_id+'] previously deleted' }), 410

    try:
        #db.session.delete(user)
        user.deleted = True
        user.delete_date = datetime_string
        db.session.commit()
    except (SQLAlchemyError, DBAPIError) as e:
        db.session.rollback()
        return jsonify({ 'message': 'Oopsy, something went wrong.'}), 500

    return jsonify({ 'message': 'Success! User ['+user.username+'] deleted.'}), 204

#------------------------------------------------------------------------------#

@bp.route('/authy/user', methods=['DELETE'])
@token_required
@require_access_level(10)
def delete_user(current_user):

    user = User.query.filter_by(public_id=current_user.public_id).first()

    ts = time.time()
    datetime_string = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    try:
        user.deleted = True
        user.delete_date = datetime_string
        db.session.commit()
    except (SQLAlchemyError, DBAPIError) as e:
        db.session.rollback()
        return jsonify({ 'message': 'Oopsy, something went wrong.'}), 500

    return jsonify({ 'message': 'Success! User ['+user.username+'] deleted.'}), 204


#------------------------------------------------------------------------------#

@bp.route('/authy/user/<public_id>/role', methods=['GET'])
@token_required
@require_access_level(5)
def get_user_roles(current_user,public_id):

    results = db.session.query(User.username,Role.name,Role.level).filter(User.id == UserRole.user_id).filter(UserRole.role_id == Role.id).filter(User.public_id == public_id).all()

    if not results:
        return jsonify({ 'message': 'User and roles not found for id ['+public_id+']' }), 404

    output = []
    username = ''

    for row in results:
        row_data = {}
        username  = row.username
        row_data['name'] = row.name
        row_data['level'] = row.level
        output.append(row_data)

    return jsonify({ 'username': username, 'public_id': public_id, 'roles': output })



#-----------------------------------------------------------------------------#
# role routes
#-----------------------------------------------------------------------------#

@bp.route('/authy/role', methods=['GET'])
@token_required
@require_access_level(5)
def get_all_roles(current_user):

    roles = Role.query.all()

    output = []

    for role in roles:
        role_data = {}
        role_data['level'] = role.level
        role_data['name'] = role.name
        role_data['description'] = role.description
        output.append(role_data)

    return jsonify({ 'roles': output })


#------------------------------------------------------------------------------#

@bp.route('/authy/role/<role_name>/users', methods=['GET'])
@token_required
@require_access_level(5)
def show_all_users_for_role(current_user, role_name):

    #TODO: Paginate this

    decoded_name = unquote(role_name)
    #app.logger.info("ROLE NAME IS [%s]",role_name)
    #app.logger.info("DECODED NAME IS [%s]",decoded_name)
    role = Role.query.filter_by(name=decoded_name).first()

    if not role:
        return jsonify({ 'message': 'Role not found.' }), 404

    role_data = {}
    role_data['level'] = role.level
    role_data['name'] = role.name
    role_data['description'] = role.description

    # get all the users for a role
    results = db.session.query(User.username,User.public_id).filter(UserRole.role_id == Role.id).filter(User.id == UserRole.user_id).filter(UserRole.role_id == role.id).all()

    output = []

    for row in results:
        row_data = {}
        row_data['name']  = row.username
        row_data['public_id'] = row.public_id
        output.append(row_data)

    return jsonify({ 'role': role_data, 'users': output })

#------------------------------------------------------------------------------#

@bp.route('/authy/role/<role_name>', methods=['GET'])
@token_required
@require_access_level(5)
def get_one_role(current_user, role_name):

    decoded_name = unquote(role_name)

    role = Role.query.filter_by(name=decoded_name).first()

    if not role:
        return jsonify({ 'message': 'Role not found.' }), 404

    role_data = {}
    role_data['level'] = role.level
    role_data['name'] = role.name
    role_data['description'] = role.description

    return jsonify({ 'role': role_data })

#------------------------------------------------------------------------------#

@bp.route('/authy/role/<role_name>/users/<public_id>', methods=['POST'])
@token_required
@require_access_level(5)
def assign_role_to_user(current_user, role_name, public_id):

    #TODO: json schema to check inputs?

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({ 'message': 'User not found'}), 404

    decoded_name = unquote(role_name)
    role = Role.query.filter_by(name=decoded_name).first()

    if not role:
        return jsonify({ 'message': 'Role not found.' }), 404

    user_role = UserRole(user_id = user.id,
                         role_id = role.id)
    try:
        db.session.add(user_role)
        db.session.commit()
    except (SQLAlchemyError, DBAPIError, UniqueViolation) as e:
        db.session.rollback()
        app.logger.debug(str(e))
        if "duplicate" in str(e):
            return jsonify({ 'message': 'User already assigned to role.'}), 400
        return jsonify({ 'message': 'Oopsy, something went wrong.'}), 500

    mess = 'Role ['+decoded_name+'] assigned to user ['+user.username+'] successfully.'
    return jsonify({ 'message': mess }), 200


#------------------------------------------------------------------------------#

@bp.route('/authy/role/<role_name>/users/<public_id>', methods=['DELETE'])
@token_required
@require_access_level(5)
def remove_user_from_role(current_user, role_name, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({ 'message': 'User not found'}), 404

    decoded_name = unquote(role_name)
    role = Role.query.filter_by(name=decoded_name).first()

    if not role:
        return jsonify({ 'message': 'Role not found.' }), 404

    user_role = UserRole.query.filter(and_(UserRole.role_id==role.id, UserRole.user_id==user.id)).first()

    if not user_role:
        return jsonify({ 'message': 'User not found with that role.' }), 404

    try:
        db.session.delete(user_role)
        db.session.commit()
    except (SQLAlchemyError, DBAPIError) as e:
        db.session.rollback()
        return jsonify({ 'message': 'Oopsy, something went wrong.'}), 500

    mess = 'User ['+user.username+'] removed from role ['+role_name+'] successfully.'
    return jsonify({ 'message': mess }), 200


#------------------------------------------------------------------------------#

@bp.route('/authy/role', methods=['POST'])
@token_required
@require_access_level(5)
def create_role(current_user):

    try:
        data = request.get_json()
    except:
        return jsonify({ 'message': 'Yer very bad, Jason' }), 400

    try:
        assert_valid_schema(data, 'role')
    except JsonValidationError as err:
        return jsonify({ 'message': 'Check ya inputs mate.', 'error': err.message }), 400

    new_role = Role(name = data['name'],
                    description = data['description'],
                    level = data['level'])

    try:
        db.session.add(new_role)
        db.session.commit()
    except (SQLAlchemyError, DBAPIError, UniqueViolation) as e:
        db.session.rollback()
        app.logger.debug(str(e))
        if "duplicate" in str(e):
            return jsonify({ 'message': 'Role already exists'}), 400
        return jsonify({ 'message': 'Oopsy, something went wrong.'}), 500

    return jsonify({ 'message': 'Success! Role ['+data['name']+'] created.'}), 201


#-----------------------------------------------------------------------------#
# system routes
#-----------------------------------------------------------------------------#

@bp.route('/authy', methods=['GET'])
def sitemap():

    output = []
    for rule in app.url_map.iter_rules():

        options = {}
        for arg in rule.arguments:
            options[arg] = "<{0}>".format(arg)

        url = url_for(rule.endpoint, **options)
        methods = list(rule.methods)
        output.append({ 'url': unquote(url), 'methods': methods })

    return jsonify({ 'endpoints': output }), 200

# -----------------------------------------------------------------------------

@bp.route('/authy/status', methods=['GET'])
def system_running():

    return jsonify({ 'message': 'System running...' })

# -----------------------------------------------------------------------------
# route for testing rate limit works - generates 429 
@bp.route('/authy/ratelimited', methods=['GET'])
@limiter.limit("0/minute")
def rate_limted(current_user):
    return jsonify({ 'message': 'should never see this' }), 200


# -----------------------------------------------------------------------------
# debug and helper functions
# -----------------------------------------------------------------------------

#def near_expiry(jwt_expiry_time):
#
#    epoch = datetime.datetime(1970,1,1)
#    i = datetime.datetime.now()
#
#    nowtime = round((i - epoch).total_seconds())
#    difference = jwt_expiry_time - nowtime
#
#    if difference < 120:
#        return True
#
#    return False


