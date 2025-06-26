from app import db, limiter
from app.models import User, Role, UserRole 
from app.assertions import assert_valid_schema
from app.main import bp
from app.services import call_aws
from flask import current_app as app

from flask import jsonify, request, abort, url_for
from werkzeug.security import generate_password_hash, check_password_hash
# from cryptography.fernet import Fernet
from functools import wraps

import uuid
import jwt
import datetime
import time
import os

from urllib.parse import unquote
from sqlalchemy.exc import SQLAlchemyError, DBAPIError
from psycopg2.errors import UniqueViolation
from sqlalchemy import func, and_ 
from jsonschema.exceptions import ValidationError as JsonValidationError

# this is a password checker from dropbox
from zxcvbn import zxcvbn

# reject all non-json requests
@bp.before_request
def only_json():
    request_path = request.path
    if request_path[:16] == '/authy/validate/':
        pass
    else:
        if not request.is_json:
            return jsonify({'message': 'Input must be json'}), 400

#-----------------------------------------------------------------------------#
# wrapper function to check if token is supplied to routes
#-----------------------------------------------------------------------------#

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        secure = False
        if 'X-Forwarded-Proto' in request.headers:
            scheme = request.headers['X-Forwarded-Proto']
            if scheme == 'HTTPS' or scheme == 'https':
                secure = True

        if app.config['ENVIRONMENT'] == 'PROD' and not secure:
            return jsonify({'message': 'La la la, I\'m not listening. All requests must be over https not http.'}), 400

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token not supplied.'}), 401
          
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS512')
            
            # get the lowest access level for the current user
            result = db.session.query(User.username,User.public_id,Role.name,Role.level)\
                     .filter(User.id == UserRole.user_id)\
                     .filter(UserRole.role_id == Role.id)\
                     .filter(User.public_id == data['public_id'])\
                     .filter(User.validated == True)\
                     .order_by(Role.level).all()
            current_user = result[0]

        except (SQLAlchemyError, jwt.InvalidTokenError, DBAPIError) as e:
            return jsonify({'message': 'Invalid token.'}), 401

        if not current_user:
            return jsonify({'message': 'Invalid token.'}), 401

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
                return jsonify({'message': 'Severe tutting ensues.'}), 401 

            return f(current_user, *args, **kwargs)

        return decorated
    return actual_decorator


#------------------------------------------------------------------------------#

#TODO: MAYBE WE SHOULD CHECK URL THE REQUEST COMES FROM TO PREVENT CROSS SITE STUFF
@bp.route('/authy/checkaccess/<external_level>', methods=['GET'])
@token_required
@require_access_level(10)
def check_access_level(current_user, external_level):

    #app.logger.info("Checking access level")

    url_string = app.config['BASE_URLS']
    good_urls = url_string.split(",")
    
    if request.host in good_urls:    

        numeric_level = 999
        try:
            numeric_level = int(external_level)
        except:
            return jsonify({'message': 'Your name\'s not down, you\'re not coming in.'}), 401

        if current_user.level <= numeric_level: 
            return jsonify({ 'public_id': current_user.public_id }), 200

    return jsonify({'message': 'Your name\'s not down, you\'re not coming in.'}), 401

#------------------------------------------------------------------------------#

#@bp.route('/authy/validate/<user_id>', methods=['GET'])
#@token_required
#@require_access_level(10)
#def check_jwt_against_user_id(current_user, user_id):
#
#    if current_user.public_id == user_id:
#        return jsonify({'message': 'On the guest list'}), 200
#
#    return jsonify({'message': 'Your name\'s not down, you\'re not coming in.'}), 401
    

# --------------------------------------------------------------------------- #
# user routes
# --------------------------------------------------------------------------- #

# log user in
@bp.route('/authy/login', methods=['POST'])
@limiter.limit("100/hour")
def login_user():

    # check input is valid json
    try:
        login_data = request.get_json()
    except:
        return jsonify({'message': 'Check ya inputs mate. Yer not valid, Jason'}), 400

    secure = False
    if 'X-Forwarded-Proto' in request.headers:
        scheme = request.headers['X-Forwarded-Proto']
        if scheme == 'HTTPS' or scheme == 'https':
            secure = True

    if app.config['ENVIRONMENT'] == 'PROD' and not secure:
        return jsonify({'message': 'La la la, I\'m not listening. All requests must be over https not http.'}), 400
    
    try:
        assert_valid_schema(login_data, 'login')
    except JsonValidationError as error:
        #TODO: WARNING - possibility of data leakage if error from
        # validation is passed on.
        app.logger.debug("The error is [%s]", str(error))
        return jsonify({'message': 'Check ya inputs mate'}), 400

    #TODO: refactor this - could do a lot of checks in the model query
    try:
        user = User.query.filter_by(username = login_data.get('username')).first()
    except: # pragma: no cover
        return jsonify({'message': 'Could not verify user'}), 401 # pragma: no cover

    # can't let 'deleted' user login
    if not user or user.deleted == True or user.validated == False:
        return jsonify({'message': 'Could not verify this user'}), 401

    # user exists so check password
    
    if check_password_hash(user.password, login_data.get('password')):
        #username = user.username.encode().decode("utf-8")
        token = jwt.encode({ 'public_id': user.public_id, 'username': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=240) }, 
                           app.config['SECRET_KEY'],
                           algorithm='HS512')

        app.logger.debug("Created JWT")
        #app.logger.debug(token)

        # update last_login field
        user.last_login = datetime.datetime.utcnow()
        try:
            db.session.commit()
            # return the token to client
            # return make_response({'token': token}, 200, {'Access-Control-Allow-Origin': '*'})
            return jsonify({ 'token': token })
        except Exception as error: # pragma: no cover
            app.logger.debug(error)
            db.session.rollback() # pragma: no cover
            return jsonify({'message': 'Oopsy something went wrong, try again'}), 500 # pragma: no cover

    return jsonify({'message': 'Could not verify user identity'}), 401

# ---------------------------------------------------------------------------- #

@bp.route('/authy/user', methods=['GET'])
@token_required
@require_access_level(10)
def get_current_user_details(current_user):

    user = User.query.filter_by(public_id = current_user.public_id).first()
    
    if not user:
        return jsonify({'message': 'hmmm, you\'re not in our records' }), 404

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['username'] = user.username
    user_data['email'] = user.email
    user_data['created'] = user.created
    user_data['last_login'] = user.last_login

    return jsonify(user_data), 200

# ---------------------------------------------------------------------------- #


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
        users = db.session.query(User).paginate(page=page, per_page=users_per_page, error_out=False).items

    except Exception as error:
        app.logger.debug(error)
        return jsonify({'message': 'oopsy, sorry we couldn\'t complete your request' }), 500

    paged_users = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['email'] = user.email
        user_data['created'] = user.created
        user_data['last_login'] = user.last_login
        user_data['validated'] = user.validated
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

# ---------------------------------------------------------------------------- #

@bp.route('/authy/user/<public_id>', methods=['GET'])
@token_required
@require_access_level(5)
def get_one_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user or user.deleted:
        return jsonify({'message': 'User not found for id ['+public_id+']' }), 404

    user_data = {}
    user_data['username'] = user.username
    user_data['email'] = user.email
    user_data['created'] = user.created
    user_data['last_login'] = user.last_login
    user_data['validated'] = user.validated    
    user_data['deleted'] = user.deleted
    user_data['delete_date'] = user.delete_date

    return jsonify(user_data)


# ---------------------------------------------------------------------------- #


@bp.route('/authy/username/<public_id>', methods=['GET'])
#@token_required
#@require_access_level(99)
def get_username(public_id):

    try:
        val = public_id[0:36]
        uuid.UUID(val, version=4)
    except ValueError:
        return jsonify({'message': 'Invalid UUID'}), 400

    user = User.query.filter_by(public_id=public_id).first()

    if not user or user.deleted:
        return jsonify({'message': 'User not found for id ['+public_id+']' }), 404

    user_data = {}
    user_data['username'] = user.username

    return jsonify(user_data)

# ---------------------------------------------------------------------------- #

@bp.route('/authy/fetch/<username>', methods=['GET'])
#@token_required
#@require_access_level(99)
def get_public_id_from_username(username):

    try:
        if len(username) > 50:
            return jsonify({'message': 'Supplied username too long'}), 400
    except Exception:
        return jsonify({'message': 'Invalid username'}), 400

    user = User.query.filter_by(username=username).first()

    if not user or user.deleted:
        return jsonify({'message': 'User not found for username' }), 404

    user_data = {}
    user_data['public_id'] = user.public_id

    return jsonify(user_data)

# ---------------------------------------------------------------------------- #

@bp.route('/authy/validate/<validation_string>', methods=['GET'])
@limiter.limit("20/hour")
def validate_user(validation_string):

    # TODO: make sure cannot validate against another user - do we need to be logged in to validate?
    # if so then need to add decorators?

    user = User.query.filter_by(validation_string=validation_string).first()

    if not user or user.deleted:
        return jsonify({'message': 'User not found' }), 404    

    try:
        user.validated = True
        user.validation_string = ''
        db.session.commit()
    except (SQLAlchemyError, DBAPIError) as e:
        app.logger.error(e)
        db.session.rollback()
        return jsonify({'message': 'Oopsy, something went wrong.'}), 500    

    return jsonify({'message': 'User validated' }), 200

# ---------------------------------------------------------------------------- #

@bp.route('/authy/user', methods=['POST'])
@limiter.limit("20/hour")
#@token_required
#@require_access_level(5)
#def create_user(current_user):
def create_user():

    app.logger.debug("create_user")

    try:
        data = request.get_json()
    except:
        return jsonify({'message': 'Check ya inputs mate. Yer not valid, Jason'}), 400

    try:
        assert_valid_schema(data, 'create_user')
    except JsonValidationError as err:
        mess = err.message
        if "does not match '[A-Z" in mess:
            mess = "Email address is not valid"
            return jsonify({'message': 'Check ya inputs mate.', 'error': mess }), 400
        return jsonify({'message': 'Check ya inputs mate', 'error': 'There was a problem with the username or password'}), 400

    # want to restrict certain usernames - get list from env
    if data['username'].lower() in app.config['RESTRICTED_USERNAMES']:
        error_message = 'Your username and/or email is already registered with us'
        return jsonify({'message': 'Oopsy, something went wrong.' , 'error': error_message }), 409

    if data['password'] != data['confirm_password']:
        return jsonify({'message': 'Passwords don\'t match'}), 400

    # password strength checking - not sure what value to accept
    results = zxcvbn(data['password'], user_inputs=[data['email'], data['username']])

    passfail = False
    if 'passfail' in data:
        passfail = True

    # return if password is too weak
    if ((app.config['ENVIRONMENT'] == 'PROD' and results.get('score') < 3) or
        (app.config['ENVIRONMENT'] == 'TEST' and results.get('score') < 3) or
        (app.config['ENVIRONMENT'] == 'DEV' and passfail)):

        new_dict = {}
        new_dict['message'] = "Sorry your password is too weak, please try another"
        new_dict['guesses'] = results['guesses']
        new_dict['feedback'] = results['feedback']
        new_dict['score'] = results['score']
        return jsonify(new_dict), 401

    validation_string = str(uuid.uuid4())+str(uuid.uuid4())+str(uuid.uuid4())+str(uuid.uuid4()) 
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha512')
    ts = time.time()
    datetime_string = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    # get a unique id for public_id and fill rest of user record
    new_user = User(public_id = str(uuid.uuid4()),
                    username = data['username'],
                    password = hashed_password,
                    validation_string = validation_string,
                    created  = datetime_string,
                    last_login = datetime_string,
                    email = data['email']) 

    #TODO: maybe we need to check for usernames that are too similar i.e. Tony and tony

    try:
        db.session.add(new_user)
        db.session.flush()
        db.session.commit()
    except (SQLAlchemyError, DBAPIError, UniqueViolation) as e:
        db.session.rollback()
        app.logger.error(str(e))
        if "duplicate" in str(e):
            error_message = 'Your username and/or email is already registered with us'
            return jsonify({'message': 'Oopsy, something went wrong.' , 'error': error_message }), 409
        else:
            error_message = 'We were unable to create your user profile'
            return jsonify({'message': 'Oopsy, something went wrong.' , 'error': error_message }), 500

    # assign 'user' role to new user
    role = Role.query.filter_by(name="user").first()
    user_role = UserRole(user_id = new_user.id,
                         role_id = role.id)

    try:
        db.session.add(user_role)
        db.session.commit()
    except (SQLAlchemyError, DBAPIError) as e: # pragma: no cover
        app.logger.error(str(e))
        db.session.rollback() # pragma: no cover

        return jsonify({'message': 'Oopsy, something went bang.'}), 500 # pragma: no cover

    # create a jwt for new user to return to client
    token = jwt.encode({ 'public_id': new_user.public_id,
                         'username': data['username'],
                         'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=240) },
                          app.config['SECRET_KEY'],
                          algorithm='HS512')

    if call_aws(token, new_user.public_id):
        return jsonify({'message': 'Success! User ['+data['username']+'] created.',
                         'token': token }), 201
    db.session.rollback() 
    return jsonify({'message': 'Oopsy, something went a bit wronger.'}), 500


#------------------------------------------------------------------------------#

#TODO: if changing password need two password fields
# and need to check various combinations 
@bp.route('/authy/user/<public_id>', methods=['PUT'])
@token_required
@require_access_level(5)
def edit_user(current_user, public_id):

    #user = User.query.filter_by(public_id=public_id).first()

    #if not user:
    #    return jsonify({'message': 'User not found for id ['+public_id+']' }), 404

    return jsonify({'message': 'Like those Levis' }), 501

#------------------------------------------------------------------------------#

@bp.route('/authy/user/<public_id>', methods=['DELETE'])
@token_required
@require_access_level(5)
def admin_delete_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    ts = time.time()
    datetime_string = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    if not user:
        return jsonify({'message': 'User not found for id ['+public_id+']' }), 404

    # if user exists but the delete flag is set ie; previously deleted then return a 410 no content
    #TODO: Maybe switch this to a 404?
    if user.deleted == True:
        return jsonify({'message': 'User ['+public_id+'] previously deleted' }), 410

    try:
        user.deleted = True
        user.delete_date = datetime_string
        db.session.commit()
    except (SQLAlchemyError, DBAPIError) as e:
        db.session.rollback()
        return jsonify({'message': 'Oopsy, something went wrong.'}), 500

    return jsonify({'message': 'Success! User ['+user.username+'] deleted.'}), 204

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
        return jsonify({'message': 'Oopsy, something went wrong.'}), 500

    return jsonify({'message': 'Success! User ['+user.username+'] deleted.'}), 204


#------------------------------------------------------------------------------#

@bp.route('/authy/user/<public_id>/role', methods=['GET'])
@token_required
@require_access_level(5)
def get_user_roles(current_user,public_id):

    try:
        val = public_id[0:36]
        uuid.UUID(val, version=4)
    except ValueError:
        return jsonify({'message': 'Invalid UUID'}), 400

    results = db.session.query(User.username,Role.name,Role.level).filter(User.id == UserRole.user_id).filter(UserRole.role_id == Role.id).filter(User.public_id == public_id).all()

    if not results:
        return jsonify({'message': 'User and roles not found for id ['+public_id+']' }), 404

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
# role routes
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
        return jsonify({'message': 'Role not found.' }), 404

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
        return jsonify({'message': 'Role not found.' }), 404

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
        return jsonify({'message': 'User not found'}), 404

    decoded_name = unquote(role_name)
    role = Role.query.filter_by(name=decoded_name).first()

    if not role:
        return jsonify({'message': 'Role not found.' }), 404

    user_role = UserRole(user_id = user.id,
                         role_id = role.id)
    try:
        db.session.add(user_role)
        db.session.commit()
    except (SQLAlchemyError, DBAPIError, UniqueViolation) as e:
        db.session.rollback()
        app.logger.debug(str(e))
        if "duplicate" in str(e):
            return jsonify({'message': 'User already assigned to role.'}), 400
        return jsonify({'message': 'Oopsy, something went wrong.'}), 500

    mess = 'Role ['+decoded_name+'] assigned to user ['+user.username+'] successfully.'
    return jsonify({'message': mess }), 200


#------------------------------------------------------------------------------#

@bp.route('/authy/role/<role_name>/users/<public_id>', methods=['DELETE'])
@token_required
@require_access_level(5)
def remove_user_from_role(current_user, role_name, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    decoded_name = unquote(role_name)
    role = Role.query.filter_by(name=decoded_name).first()

    if not role:
        return jsonify({'message': 'Role not found.' }), 404

    user_role = UserRole.query.filter(and_(UserRole.role_id==role.id, UserRole.user_id==user.id)).first()

    if not user_role:
        return jsonify({'message': 'User not found with that role.' }), 404

    try:
        db.session.delete(user_role)
        db.session.commit()
    except (SQLAlchemyError, DBAPIError) as e:
        db.session.rollback()
        return jsonify({'message': 'Oopsy, something went wrong.'}), 500

    mess = 'User ['+user.username+'] removed from role ['+role_name+'] successfully.'
    return jsonify({'message': mess }), 200


#------------------------------------------------------------------------------#

@bp.route('/authy/role', methods=['POST'])
@token_required
@require_access_level(5)
def create_role(current_user):

    data = request.get_json()

    try:
        assert_valid_schema(data, 'role')
    except JsonValidationError as err:
        return jsonify({'message': 'Check ya inputs mate.', 'error': err.message }), 400

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
            return jsonify({'message': 'Role already exists'}), 400
        return jsonify({'message': 'Oopsy, something went wrong.'}), 500

    return jsonify({'message': 'Success! Role ['+data['name']+'] created.'}), 201


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

    return jsonify({'message': 'System running...', 'version': os.getenv('VERSION')})
    # return make_response({'message': 'System running...'}, 200, {'Access-Control-Allow-Origin': '*'})

# -----------------------------------------------------------------------------
# route for testing rate limit works - generates 429 
@bp.route('/authy/ratelimited', methods=['GET'])
@limiter.limit("0/minute")
def rate_limted(current_user):
    return jsonify({'message': 'should never see this' }), 200


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


