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
####                      flask test case instance                         ####
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
####                               tests                                   ####
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
        roles = []
        roles = Role.query.all()
        self.assertEqual(len(roles), 4)
        users = []
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
        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json)

# -----------------------------------------------------------------------------

    def test_utf8_login_ok(self):
        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="分支持",
                                                   passwd="password"),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json)

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

    def test_login_fails_bad_password(self):
        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="mandy",
                                                   passwd="wrongpass"),
                                   headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 401)
        self.assertEqual(data.get('message'), "Could not verify user identity")

# -----------------------------------------------------------------------------

    def test_deleted_user_fail_login(self):
        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="harry",
                                                   passwd="password"),
                                   headers=headers)        
        self.assertEqual(response.status_code, 401)

# -----------------------------------------------------------------------------

    def test_can_get_own_user_data(self):
        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="sally",
                                                   passwd="password"),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json

        response = self.client.get('/authy/user', 
                                   headers=headers_with_token(data['token']))
        self.assertEqual(response.status_code, 200)
        user_data = response.json

        self.assertEqual(user_data["username"], "sally")
        self.assertEqual(user_data["email"], "sally@email.com")

# -----------------------------------------------------------------------------

    def test_invalid_token(self):
        users = addNormalUsers()
        response = self.client.get('/authy/user',
                                   headers=headers_with_token('invalid_token'))
        self.assertEqual(response.status_code, 401)
        user_data = response.json
        self.assertEqual(user_data["message"], "Invalid token.")

# -----------------------------------------------------------------------------

    def test_invalid_token_wrong_users_token(self):
        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="sally",
                                                   passwd="password"),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json

        url = '/authy/user/'+users[5].public_id
        response = self.client.get(url,
                                   headers=headers_with_token(data['token']))
        self.assertEqual(response.status_code, 401)
        user_data = response.json
        self.assertEqual(user_data["message"], "Severe tutting ensues.")

# -----------------------------------------------------------------------------

    def test_normal_user_cannot_get_list_all_users(self):
        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="sally",
                                                   passwd="password"),
                                   headers=headers)        
        self.assertEqual(response.status_code, 200)
        data = response.json

        response = self.client.get('/authy/users', 
                                   headers=headers_with_token(data['token']))
        self.assertEqual(response.status_code, 401)

# -----------------------------------------------------------------------------

    def test_admin_user_get_list_all_users(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="clivey",
                                                   passwd="password"),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json

        response = self.client.get('/authy/users',
                                   headers=headers_with_token(data['token']))
        self.assertEqual(response.status_code, 200)
        data = response.json
        self.assertEqual(data.get('total_records'), 10)
        users_per_page = int(TestConfig.USERS_LIMIT_PER_PAGE)
        self.assertEqual(len(data.get('users')), users_per_page)
        self.assertEqual(data.get('next_url'), "/authy/users?page=2")

# -----------------------------------------------------------------------------

    def test_rate_limiting(self):
        headers = { 'Content-type': 'application/json' }
        response = self.client.get('/authy/ratelimited',
                                   headers=headers)
        self.assertEqual(response.status_code, 429)

# -----------------------------------------------------------------------------

    def test_admin_get_single_user_details(self):

        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="bobby",
                                                   passwd="password"),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json
        url = '/authy/user/' + users[6].public_id
        response2 = self.client.get(url,
                                   headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 200)
        user_data = response2.json

        self.assertEqual(user_data['username'], users[6].username)
        self.assertEqual(user_data['email'], users[6].email)
        self.assertEqual(user_data['deleted'], users[6].deleted)
        self.assertEqual(user_data['delete_date'], users[6].delete_date)

# -----------------------------------------------------------------------------

    def test_validate_user(self):

        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="lucky",
                                                   passwd="password"),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json
        url = '/authy/validate/' + users[5].public_id
        response2 = self.client.get(url,
                                   headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 200)

# -----------------------------------------------------------------------------

    def test_validate_user_restriction(self):

        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="lucky",
                                                   passwd="password"),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json
        url = '/authy/validate/' + users[3].public_id
        response2 = self.client.get(url,
                                   headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 401)

# -----------------------------------------------------------------------------

    def test_check_access_ok(self):

        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="lucky",
                                                   passwd="password"),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json
        url = '/authy/checkaccess/10'
        response2 = self.client.get(url,
                                   headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 200)

# -----------------------------------------------------------------------------

    def test_check_access_fail_1(self):

        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="sally",
                                                   passwd="password"),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json
        url = '/authy/checkaccess/5'
        response2 = self.client.get(url,
                                   headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 401)


# -----------------------------------------------------------------------------

    def test_check_access_fail_2(self):

        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="sally",
                                                   passwd="password"),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json
        url = '/authy/checkaccess/asas'
        response2 = self.client.get(url,
                                   headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 401)

# -----------------------------------------------------------------------------

    def test_user_roles_returned_ok_for_admin(self):

        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="clivey",
                                                   passwd="password"),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json
        url = '/authy/user/'+users[0].public_id+'/role'
        response2 = self.client.get(url,
                                   headers=headers_with_token(data['token']))
        role_data = response2.json
        self.assertEqual(response2.status_code, 200)

# -----------------------------------------------------------------------------

    def test_role_returned_fail_for_wrong_user_if_not_admin(self):

        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="woody",
                                                   passwd="password"),
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json
        url = '/authy/user/'+users[1].public_id+'/role'
        response2 = self.client.get(url,
                                   headers=headers_with_token(data['token']))
        role_data = response2.json
        self.assertEqual(response2.status_code, 401)

# -----------------------------------------------------------------------------

    def test_create_user_ok(self):

        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        create_user = { 'username': 'user1',
                        'password': 'hgfkwyg322dd',
                        'confirm_password': 'hgfkwyg322dd',
                        'email': 'user1@email.com' }
        response = self.client.post('/authy/user',
                                   json=create_user,
                                   headers=headers)
        self.assertEqual(response.status_code, 201)

# -----------------------------------------------------------------------------

    def test_create_user_fail_due_to_weak_password(self):

        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        create_user = { 'username': 'user1',
                        'password': 'password',
                        'confirm_password': 'password',
                        'email': 'user1@email.com' }
        response = self.client.post('/authy/user',
                                   json=create_user,
                                   headers=headers)
        self.assertEqual(response.status_code, 401)
        data = response.json
        self.assertEqual(data.get('message'), "Sorry your password is too weak, please try another")

# -----------------------------------------------------------------------------

    def test_create_user_fail_passwords_do_not_match(self):

        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        create_user = { 'username': 'user1',
                        'password': 'hdqi73dhksdd',
                        'confirm_password': 'hdqi73dhksd',
                        'email': 'user1@email.com' }
        response = self.client.post('/authy/user',
                                   json=create_user,
                                   headers=headers)
        self.assertEqual(response.status_code, 400)
        data = response.json
        self.assertEqual(data.get('message'), "Passwords don\'t match")

# -----------------------------------------------------------------------------

    def test_create_fail_bad_email(self):

        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        create_user = { 'username': 'user1',
                        'password': 'hgfkwyg322dd',
                        'confirm_password': 'hgfkwyg322dd',
                        'email': 'user1@email' }
        response = self.client.post('/authy/user',
                                   json=create_user,
                                   headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 400)
        self.assertEqual(data.get('error'), "Email address is not valid")

# -----------------------------------------------------------------------------

    def test_create_fail_duplicate_username(self):

        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        create_user = { 'username': 'woody',
                        'password': 'hgfkwyg322dd',
                        'confirm_password': 'hgfkwyg322dd',
                        'email': 'woody12@email.com' }
        response = self.client.post('/authy/user',
                                   json=create_user,
                                   headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 409)
        self.assertEqual(data.get('error'), 
                "Your username and/or email is already registered with us")

# -----------------------------------------------------------------------------

    def test_create_fail_duplicate_email(self):

        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        create_user = { 'username': 'woodyh',
                        'password': 'hgfkwyg322dd',
                        'confirm_password': 'hgfkwyg322dd',
                        'email': 'woody@email.com' }
        response = self.client.post('/authy/user',
                                   json=create_user,
                                   headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 409)
        self.assertEqual(data.get('error'), 
                "Your username and/or email is already registered with us")

# -----------------------------------------------------------------------------

    def test_delete_user_ok(self):
        users = addNormalUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="woody",
                                                   passwd="password"),
                                   headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        response2 = self.client.delete('/authy/user',
                                       headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 204)

# -----------------------------------------------------------------------------

    def test_admin_delete_user_ok(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="clivey",
                                                   passwd="password"),
                                   headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/user/'+users[0].public_id
        response2 = self.client.delete(url,
                                       headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 204)

# -----------------------------------------------------------------------------

    def test_admin_delete_user_404(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="clivey",
                                                   passwd="password"),
                                   headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/user/hdjqwdgjhdg89d7d987w9d'
        response2 = self.client.delete(url,
                                       headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 404)

# -----------------------------------------------------------------------------

    def test_non_admin_cannot_delete_other_user(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="woody",
                                                   passwd="password"),
                                   headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/user/'+users[1].public_id
        response2 = self.client.delete(url,
                                       headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 401)

# -----------------------------------------------------------------------------

    def test_admin_return_all_roles(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role'
        response2 = self.client.get(url,
                                    headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 200)

# -----------------------------------------------------------------------------

    def test_admin_return_role_details(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="clivey",
                                                   passwd="password"),
                                   headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/user'
        response2 = self.client.get(url,
                                    headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 200)

# -----------------------------------------------------------------------------

    def test_admin_return_404_for_nonexistent_role_details(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="clivey",
                                                   passwd="password"),
                                   headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/noexisty'
        response2 = self.client.get(url,
                                    headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 404)

# -----------------------------------------------------------------------------

    def test_normal_user_get_roles_fail(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="woody",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role'
        response2 = self.client.get(url,
                                    headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 401)

# -----------------------------------------------------------------------------

    def test_normal_user_get_role_details_fail(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                   json=login_body(name="woody",
                                                   passwd="password"),
                                   headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/user'
        response2 = self.client.get(url,
                                    headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 401)

# -----------------------------------------------------------------------------

    def test_admin_return_all_users_for_role(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/user/users'
        response2 = self.client.get(url,
                                    headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 200)
        data = response2.json
        role_data = data.get("role")
        self.assertEqual(role_data.get("name"), "user")
        self.assertEqual(len(data.get("users")), 8)

# -----------------------------------------------------------------------------

    def test_admin_return_404_for_nonexistent_role(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/wibble/users'
        response2 = self.client.get(url,
                                    headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 404)

# -----------------------------------------------------------------------------

    def test_normal_user_return_all_users_for_role_fail(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="woody",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/user/users'
        response2 = self.client.get(url,
                                    headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 401)

# -----------------------------------------------------------------------------

    def test_admin_assign_user_to_role_ok(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/admin/users/'+users[0].public_id
        response2 = self.client.post(url,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 200)
        data = response2.json
        self.assertIn(users[0].username, data.get('message'))
        self.assertIn("user", data.get('message'))

# -----------------------------------------------------------------------------

    def test_admin_assign_user_to_role_fail_already_assigned(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/user/users/'+users[0].public_id
        response2 = self.client.post(url,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 400)
        data = response2.json
        self.assertIn("User already assigned to role", data.get('message'))

# -----------------------------------------------------------------------------

    def test_admin_assign_user_to_role_fail_bad_role(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/bling/users/'+users[0].public_id
        response2 = self.client.post(url,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 404)

# -----------------------------------------------------------------------------

    def test_admin_assign_user_to_role_fail_bad_public_id(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/user/users/dsalkdhakldhkashjd'
        response2 = self.client.post(url,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 404)

# -----------------------------------------------------------------------------

    def test_admin_delete_user_from_role_ok(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/user/users/'+users[0].public_id
        response2 = self.client.delete(url,
                                       headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 200)

# -----------------------------------------------------------------------------

    def test_normal_user_delete_user_from_role_fail(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="woody",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/user/users/'+users[1].public_id
        response2 = self.client.delete(url,
                                       headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 401)

# -----------------------------------------------------------------------------

    def test_admin_delete_user_from_role_fail_bad_role(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/badrole/users/'+users[0].public_id
        response2 = self.client.delete(url,
                                       headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 404)

# -----------------------------------------------------------------------------

    def test_admin_delete_user_from_role_fail_bad_user(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/user/users/dasdadadads'
        response2 = self.client.delete(url,
                                       headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 404)

# -----------------------------------------------------------------------------

    def test_admin_delete_user_from_role_fail_user_not_in_role(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role/admin/users/'+users[0].public_id
        response2 = self.client.delete(url,
                                       headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 404)

# -----------------------------------------------------------------------------

    def test_admin_create_role_ok(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role'
        new_role = { 'name': 'megaguest', 'description': 'Mega guest', 'level': 15 }
        response2 = self.client.post(url,
                                     json=new_role,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 201)

# -----------------------------------------------------------------------------

    def test_normal_user_create_role_fail(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="mandy",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role'
        new_role = { 'name': 'megaguest', 'description': 'Mega guest', 'level': 15 }
        response2 = self.client.post(url,
                                     json=new_role,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 401)

# -----------------------------------------------------------------------------

    def test_admin_create_role_fail_bad_level(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role'
        new_role = { 'name': 'megaguest', 'description': 'Mega guest', 'level': 'a' }
        response2 = self.client.post(url,
                                     json=new_role,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 400)

# -----------------------------------------------------------------------------

    def test_admin_create_role_fail_description_too_long(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role'
        new_role = { 'name': 'megaguest', 
                     'description': 'A very long description. A very long description. \
                     A very long description. A very long description. A very long description. ',
                     'level': 15 }
        response2 = self.client.post(url,
                                     json=new_role,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 400)

# -----------------------------------------------------------------------------

    def test_admin_create_role_fail_duplicate_fail(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/role'
        new_role = { 'name': 'user',
                     'description': 'A description.',
                     'level': 15 }
        response2 = self.client.post(url,
                                     json=new_role,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 400)

# -----------------------------------------------------------------------------

    def test_site_map(self):
        headers = { 'Content-type': 'application/json' }
        response = self.client.get('/authy',
                                    headers=headers)
        self.assertEqual(response.status_code, 200)
        
# -----------------------------------------------------------------------------

    def test_checkaccess_ok(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="mandy",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/checkaccess/10'
        response2 = self.client.get(url,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 200)

# -----------------------------------------------------------------------------

    def test_check_access_fail(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="mandy",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/checkaccess/5'
        response2 = self.client.get(url,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 401)

# -----------------------------------------------------------------------------

    def test_check_access_fail_level(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="mandy",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/checkaccess/sasas'
        response2 = self.client.get(url,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 401)

# -----------------------------------------------------------------------------

    def test_login_bad_json(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        bad_data = '{ "badjson: "true" }'
        response = self.client.post('/authy/login',
                                    data=bad_data,
                                    headers=headers)
        self.assertEqual(response.status_code, 400)






