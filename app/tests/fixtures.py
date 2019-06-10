# app/tests/fixtures.py

from app import db
from app.models import User, Role, UserRole
import uuid
import os.path
import datetime
import time
from requests.auth import _basic_auth_str
from werkzeug.security import generate_password_hash, check_password_hash

# users and roles for testing

# -----------------------------------------------------------------------------

def make_datetime_string():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

# -----------------------------------------------------------------------------

def login_body(**kwargs):

    if "name" and "passwd" in kwargs:
        return { 'username': kwargs['name'], 'password': kwargs['passwd'] }

    return { 'username': 'woody', 'password': 'password' }

# -----------------------------------------------------------------------------

def headers_with_token(token):

    headers = { 'Content-type': 'application/json',
                'x-access-token': token }
    return headers    

# -----------------------------------------------------------------------------

def addTestRoles():
    role1 = Role(name = "superadmin", description = "God level", level=0)
    role2 = Role(name = "admin", description = "Minor Deity", level=1)
    role3 = Role(name = "user", description = "User", level=10)
    role4 = Role(name = "guest", description = "Guest", level=99)
    db.session.add(role1)
    db.session.add(role2)
    db.session.add(role3)
    db.session.add(role4)
    roles = [role1, role2, role3, role4]
    db.session.commit()
    return roles

# -----------------------------------------------------------------------------

def addNormalUsers():

    # check if countries are present and if not then add them
    roles = []
    roles = Role.query.all()
    if len(roles) == 0:
        roles = addTestRoles()

    user1 = User(public_id = str(uuid.uuid4()),
                 username = 'woody',
                 password = generate_password_hash('password'),
                 created  = make_datetime_string(),
                 last_login = make_datetime_string(),
                 email = 'woody@email.com')

    user2 = User(public_id = str(uuid.uuid4()),
                 username = 'mandy',
                 password = generate_password_hash('password'),
                 created  = make_datetime_string(),
                 last_login = make_datetime_string(),
                 email = 'mandy@email.com')

    user3 = User(public_id = str(uuid.uuid4()),
                 username = 'harry',
                 password = generate_password_hash('password'),
                 created  = make_datetime_string(),
                 last_login = make_datetime_string(),
                 deleted = True,
                 delete_date = make_datetime_string(),
                 email = 'harry@email.com')

    user4 = User(public_id = str(uuid.uuid4()),
                 username = 'sally',
                 password = generate_password_hash('password'),
                 created  = make_datetime_string(),
                 last_login = make_datetime_string(),
                 email = 'sally@email.com')

    user5 = User(public_id = str(uuid.uuid4()),
                 username = 'mary',
                 password = generate_password_hash('password'),
                 created  = make_datetime_string(),
                 last_login = make_datetime_string(),
                 email = 'mary@email.com')

    user6 = User(public_id = str(uuid.uuid4()),
                 username = 'lucky',
                 password = generate_password_hash('password'),
                 created  = 'Sun, 09 Jun 2019 18:33:32 GMT',
                 last_login = 'Sun, 09 Jun 2019 18:33:32 GMT',
                 email = 'lucky@email.com')

    user7 = User(public_id = str(uuid.uuid4()),
                 username = 'brüna',
                 password = generate_password_hash('password'),
                 created  = 'Sun, 09 Jun 2019 18:33:32 GMT',
                 last_login = make_datetime_string(),
                 email = 'brüna@email.com')

    user8 = User(public_id = str(uuid.uuid4()),
                 username = '分支持',
                 password = generate_password_hash('password'),
                 created  = make_datetime_string(),
                 last_login = make_datetime_string(),
                 email = 'djing@email.com')

    db.session.add(user1)
    db.session.add(user2)
    db.session.add(user3)
    db.session.add(user4)
    db.session.add(user5)
    db.session.add(user6)
    db.session.add(user7)
    db.session.add(user8)
    db.session.commit()

    users = [user1, user2, user3, user4, user5, user6, user7, user8]
   
    # add all users to users role
    for user in users:
        userole = UserRole(user_id = user.id, role_id=3)
        db.session.add(userole)

    db.session.commit()

    return users

# -----------------------------------------------------------------------------

def addAdminUsers():

    # check if roles are present and if not then add them
    roles = []
    roles = Role.query.all()
    if len(roles) == 0:
        roles = addTestRoles() # pragma: no cover

    user1 = User(public_id = str(uuid.uuid4()),
                 username = 'clivey',
                 password = generate_password_hash('password'),
                 created  = make_datetime_string(),
                 last_login = make_datetime_string(),
                 email = 'clivey@email.com')

    user2 = User(public_id = str(uuid.uuid4()),
                 username = 'bobby',
                 password = generate_password_hash('password'),
                 created  = make_datetime_string(),
                 last_login = make_datetime_string(),
                 email = 'bobby@email.com')

    db.session.add(user1)
    db.session.add(user2)
    db.session.commit()

    users = [user1, user2]

    # add all users to two admin roles
    userole1 = UserRole(user_id = user1.id, role_id=1)
    userole2 = UserRole(user_id = user2.id, role_id=2)
    db.session.add(userole1)
    db.session.add(userole2)

    db.session.commit()


