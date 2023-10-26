# app/tests/test_api.py
from mock import patch
from functools import wraps
from flask import jsonify

from app import create_app, db
from app.models import User, Role, UserRole
from app.config import TestConfig
from .fixtures import addNormalUsers, addAdminUsers, headers_with_token
from .fixtures import login_body, make_datetime_string

from flask import current_app 
from flask_testing import TestCase as FlaskTestCase

import uuid
from werkzeug.security import generate_password_hash, check_password_hash

###############################################################################
#                         flask test case instance                            #
###############################################################################

class MyTest(FlaskTestCase):

    ############################
    #### setup and teardown ####
    ############################

    def create_app(self):
        app = create_app(TestConfig)
        return app

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

###############################################################################
#                                tests                                        #
###############################################################################

    def test_status_ok(self):
        headers = { 'Content-type': 'application/json' }
        response = self.client.get('/authy/status', headers=headers)

        self.assertEqual(response.status_code, 200)

# -----------------------------------------------------------------------------

    def test_404(self):
        # this behaviour is slightly different to live as we've mocked the 
        headers = { 'Content-type': 'application/json' }
        response = self.client.get('/authy/resourcenotfound', headers=headers)
        self.assertEqual(response.status_code, 404)
        self.assertTrue(response.is_json)

# -----------------------------------------------------------------------------

    def test_api_rejects_html_input(self):
        headers = { 'Content-type': 'text/html' }
        response = self.client.get('/authy/status', headers=headers)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.is_json)

# -----------------------------------------------------------------------------

    def test_wrong_method_error_returns_json(self):
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/status', json={ 'test': 1 }, headers=headers)
        self.assertEqual(response.status_code, 405)
        self.assertTrue(response.is_json)

# -----------------------------------------------------------------------------

    def test_database_loads_ok(self):
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)
        print('No of added users is: '+str(len(added_users)))
        #roles = []
        roles = Role.query.all()
        self.assertEqual(len(roles), 4)
        #users = []
        users = User.query.all()
        self.assertEqual(len(users), 8)

# -----------------------------------------------------------------------------

    def test_user_model_saves_ok(self):
        user1 = User(public_id = str(uuid.uuid4()),
                     username = 'woody',
                     password = generate_password_hash('password'),
                     created  = make_datetime_string(),
                     last_login = make_datetime_string(),
                     email = 'woody@email.com')
        db.session.add(user1)
        db.session.commit()
        self.assertEqual(user1.id, 1)

    # -----------------------------------------------------------------------------

    def test_role_model_saves_ok(self):
        role1 = Role(name = "superadmin", description = "God level", level=0)
        db.session.add(role1)
        db.session.commit()
        self.assertEqual(role1.id, 1)

    # -----------------------------------------------------------------------------

    def test_userrole_model_saves_ok(self):
        role1 = Role(name = "superadmin", description = "God level", level=0)
        user1 = User(public_id = str(uuid.uuid4()),
                     username = 'woody',
                     password = generate_password_hash('password'),
                     created  = make_datetime_string(),
                     last_login = make_datetime_string(),
                     email = 'woody@email.com')
        db.session.add(user1)
        db.session.add(role1)
        db.session.commit()

        userole = UserRole(user_id = user1.id, role_id = role1.id)
        db.session.add(userole)

        db.session.commit()
        self.assertEqual(userole.user_id, user1.id)
        self.assertEqual(userole.role_id, role1.id)

    # -----------------------------------------------------------------------------

    def test_401_for_an_unauthenticated_user(self):
        headers = { 'Content-type': 'application/json' }
        url = "/authy/user"
        response = self.client.get(url, headers=headers)
        self.assertEqual(response.status_code, 401)

    # -----------------------------------------------------------------------------

    def test_cannot_login_with_wrong_pass(self):
        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="sally",
                                                    passwd="pAssword"),
                                    headers=headers)
        self.assertEqual(response.status_code, 401)

    # -----------------------------------------------------------------------------

    def test_cannot_login_with_user_that_does_not_exist(self):
        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="ronald",
                                                    passwd="password"),
                                    headers=headers)
        print(response.json)
        self.assertEqual(response.status_code, 401)

    # -----------------------------------------------------------------------------

    def test_login_ok(self):
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)
        print('\n\nNo of added users is: '+str(len(added_users))+'\n\n')
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(),
                                    headers=headers)

        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json)

    # -----------------------------------------------------------------------------

#    def test_utf8_login_ok(self):
#        users = addNormalUsers()
#        headers = { 'Content-type': 'application/json' }
#        response = self.client.post('/authy/login',
#                                    json=login_body(name="分支持",
#                                                    passwd="password"),
#                                    headers=headers)
#        self.assertEqual(response.status_code, 200)
#        self.assertIn('token', response.json)

    # -----------------------------------------------------------------------------

    def test_login_fails_bad_json(self):
        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        bad_string = '{ "bad" "json }'
        response = self.client.post('/authy/login',
                                    json=bad_string,
                                    headers=headers)
        self.assertEqual(response.status_code, 400)

    # -----------------------------------------------------------------------------

    def test_login_fails_user_not_existing(self):
        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="pigsy",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 401)
        self.assertEqual(data.get('message'), "Could not verify this user")

# -----------------------------------------------------------------------------
