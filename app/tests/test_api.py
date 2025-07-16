# app/tests/test_api.py
# from mock import patch, MagicMock
from unittest import mock

from app import create_app, db
from app.models import User, Role, UserRole
from app.config import TestConfig
from .fixtures import addNormalUsers, addAdminUsers, headers_with_token
from .fixtures import login_body, make_datetime_string, headers_with_token_and_https

from flask_testing import TestCase as FlaskTestCase

import uuid
import base64
from werkzeug.security import generate_password_hash, check_password_hash

# this method will be used by the mock to replace requests.get
def mocked_requests_post(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    if args[0] == 'https://poptape.club/aws/user':
        return MockResponse({"key1": "value1"}, 201)

    return MockResponse(None, 404)

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
        roles = Role.query.all()
        self.assertEqual(len(roles), 4)
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
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="sally",
                                                    passwd='pAssword'),
                                    headers=headers)
        self.assertEqual(response.status_code, 401)

    # -----------------------------------------------------------------------------

    def test_cannot_login_with_user_that_does_not_exist(self):
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="ronald",
                                                    passwd='password'),
                                    headers=headers)
        self.assertEqual(response.status_code, 401)

    # -----------------------------------------------------------------------------

    def test_login_ok(self):
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)

        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(),
                                    headers=headers)

        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json)

    # -----------------------------------------------------------------------------

    def test_utf8_login_ok(self):
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="分支持",
                                                    passwd="分支持"),
                                    headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json)

    # -----------------------------------------------------------------------------

    def test_login_fails_bad_json(self):
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)
        headers = { 'Content-type': 'application/json' }
        bad_string = '{ "bad" "json }'
        response = self.client.post('/authy/login',
                                    json=bad_string,
                                    headers=headers)
        self.assertEqual(response.status_code, 400)

    # -----------------------------------------------------------------------------

    def test_login_fails_user_not_existing(self):
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)
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
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)
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
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="harry",
                                                    passwd="password"),
                                    headers=headers)
        self.assertEqual(response.status_code, 401)

    # -----------------------------------------------------------------------------

    def test_https_setting_on_login(self):
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)
        headers = {'Content-type': 'application/json',
                   'X-Forwarded-Proto': 'https'}
        response = self.client.post('/authy/login',
                                    json=login_body(name="sally",
                                                    passwd="password"),
                                    headers=headers)
        self.assertEqual(response.status_code, 200)

    # -----------------------------------------------------------------------------

    def test_https_setting_on_token_required(self):
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="sally",
                                                    passwd="password"),
                                    headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json

        response = self.client.get('/authy/user',
                                   headers=headers_with_token_and_https(data['token']))
        self.assertEqual(response.status_code, 200)

    # -----------------------------------------------------------------------------

    def test_invalid_token(self):
        added_users = addNormalUsers()
        self.assertEqual(len(added_users), 8)
        response = self.client.get('/authy/user',
                                   headers=headers_with_token('invalid_token'))
        self.assertEqual(response.status_code, 401)
        user_data = response.json
        self.assertEqual(user_data["message"], "Invalid token.")

    # -----------------------------------------------------------------------------

    def test_invalid_token_wrong_users_token(self):
        users = addNormalUsers()
        self.assertEqual(len(users), 8)
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
        self.assertEqual(len(users), 8)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="lucky",
                                                    passwd="password"),
                                    headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json
        url = '/authy/validate/blahblah48732947'
        response2 = self.client.get(url,
                                    headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 200)

    # -----------------------------------------------------------------------------

    def test_validate_user_restriction(self):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(response2.status_code, 404)

    # -----------------------------------------------------------------------------

    def test_check_access_ok(self):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        # role_data = response2.json
        self.assertEqual(response2.status_code, 200)

    # -----------------------------------------------------------------------------

    def test_role_returned_fail_for_wrong_user_if_not_admin(self):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
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

    @mock.patch('requests.post', side_effect=mocked_requests_post)
    def test_create_user_ok(self, mock_post):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
        headers = { 'Content-type': 'application/json' }
        create_user = {'username': 'user1',
                       'password': 'hgfkwyg322dd',
                       'confirm_password': 'hgfkwyg322dd',
                       'email': 'user1@email.com'}
        response = self.client.post('/authy/user',
                                    json=create_user,
                                    headers=headers)
        self.assertEqual(len(mock_post.call_args_list), 1)
        self.assertEqual(response.status_code, 201)

    # -----------------------------------------------------------------------------

    @mock.patch('requests.post', side_effect=mocked_requests_post)
    def test_create_user_ok_passfail(self, mock_post):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
        headers = { 'Content-type': 'application/json' }
        create_user = {'username': 'userX',
                       'password': 'password',
                       'confirm_password': 'password',
                       'passfail': 1,
                       'email': 'userX@email.com'}
        response = self.client.post('/authy/user',
                                    json=create_user,
                                    headers=headers)
        self.assertEqual(response.status_code, 401)

    # -----------------------------------------------------------------------------

    @mock.patch('requests.post', side_effect=mocked_requests_post)
    def test_create_user_fail_restricted_name(self, mock_post):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
        headers = { 'Content-type': 'application/json' }
        create_user = {'username': 'admin',
                       'password': 'hgfkwyg322dd',
                       'confirm_password': 'hgfkwyg322dd',
                       'email': 'user1@email.com'}
        response = self.client.post('/authy/user',
                                    json=create_user,
                                    headers=headers)
        self.assertEqual(response.status_code, 409)

    # -----------------------------------------------------------------------------

    @mock.patch('requests.post', side_effect=mocked_requests_post)
    def test_create_user_fail_bad_json(self, mock_post):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/user',
                                    json='bbb',
                                    headers=headers)
        self.assertEqual(response.status_code, 400)

    # -----------------------------------------------------------------------------

    @mock.patch('requests.post', side_effect=mocked_requests_post)
    def test_create_user_fail_json_not_match_schema(self, mock_post):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
        headers = { 'Content-type': 'application/json' }
        create_user = {'username': 'user1',
                       'password': 'hgfkwyg322dd',
                       'confirm_password': 'hgfkwyg322dd',
                       'blah': 'yarp',
                       'email': 'user1@email.com'}
        response = self.client.post('/authy/user',
                                    json=create_user,
                                    headers=headers)
        self.assertEqual(response.status_code, 400)

    # -----------------------------------------------------------------------------
    def test_create_user_fail_due_to_weak_password(self):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
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
        self.assertEqual(len(users), 8)
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
        self.assertEqual(len(users), 8)
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
        self.assertEqual(len(users), 8)
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
        self.assertEqual(len(users), 8)
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
        self.assertEqual(len(users), 8)
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

    def test_admin_delete_user_fail_already_deleted(self):

        users = addNormalUsers()
        addAdminUsers()
        self.assertEqual(len(users), 8)
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="bobby",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/user/'+users[0].public_id
        response2 = self.client.delete(url,
                                       headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 204)
        # try and delete again
        url = '/authy/user/'+users[0].public_id
        response3 = self.client.delete(url,
                                       headers=headers_with_token(data['token']))
        self.assertEqual(response3.status_code, 410)

    # -----------------------------------------------------------------------------

    def test_admin_get_roles_for_bad_public_id(self):

        users = addNormalUsers()
        addAdminUsers()
        self.assertEqual(len(users), 8)
        headers = {'Content-type': 'application/json'}
        response = self.client.post('/authy/login',
                                    json=login_body(name="bobby",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/user/hksfirkykifhdawkdfaw/role'
        response2 = self.client.get(url,
                                    headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 400)

    # -----------------------------------------------------------------------------

    def test_admin_get_roles_for_non_existent_user(self):

        users = addNormalUsers()
        addAdminUsers()
        self.assertEqual(len(users), 8)
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="bobby",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/user/'+str(uuid.uuid4())+'/role'
        response2 = self.client.get(url,
                                    headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 404)

    # -----------------------------------------------------------------------------

    def test_edit_user(self):

        users = addNormalUsers()
        addAdminUsers()
        self.assertEqual(len(users), 8)
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="bobby",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        edit_user = {'email': 'woody2@email.com'}
        url = '/authy/user/'+users[0].public_id
        response2 = self.client.put(url,
                                    json=edit_user,
                                    headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 501)

    # -----------------------------------------------------------------------------

    def test_admin_delete_user_ok(self):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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

    def test_get_username_from_public_id(self):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
        headers = {'Content-type': 'application/json'}
        url = '/authy/username/'+users[0].public_id
        response = self.client.get(url,
                                   headers=headers)
        data = response.json
        username = data.get("username")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(users[0].username, username)

    # -----------------------------------------------------------------------------

    def test_username_not_found_from_uuid(self):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
        headers = {'Content-type': 'application/json'}
        url = '/authy/username/'+str(uuid.uuid4())
        response = self.client.get(url,
                                   headers=headers)
        self.assertEqual(response.status_code, 404)

    # -----------------------------------------------------------------------------

    def test_invalid_uuid_in_get_username_from_public_id(self):

        # try too long string
        headers = {'Content-type': 'application/json'}
        url = '/authy/username/1234567890123456789012345678901234567890'
        response = self.client.get(url,
                                   headers=headers)
        self.assertEqual(response.status_code, 400)

        # try too short
        url = '/authy/username/12345678901234567890'
        response = self.client.get(url,
                               headers=headers)
        self.assertEqual(response.status_code, 400)

        # try right length but invalid
        url = '/authy/username/9b4bd53d-0b50-4847-95i9-696f31508694'
        response = self.client.get(url,
                                   headers=headers)
        self.assertEqual(response.status_code, 400)

    # -----------------------------------------------------------------------------

    def test_get_public_id_from_username(self):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
        headers = {'Content-type': 'application/json'}
        url = '/authy/fetch/'+users[0].username
        response = self.client.get(url,
                                   headers=headers)
        returned_data = response.json
        self.assertEqual(response.status_code, 200)
        self.assertEqual(users[0].public_id, returned_data.get("public_id"))

    # -----------------------------------------------------------------------------

    def test_return_404_get_public_id_from_username(self):

        headers = {'Content-type': 'application/json'}
        url = '/authy/fetch/someuserthatdoesnotexist'
        response = self.client.get(url,
                                   headers=headers)
        self.assertEqual(response.status_code, 404)

    # -----------------------------------------------------------------------------

    def test_return_400_get_public_id_from_username(self):

        headers = {'Content-type': 'application/json'}
        url = '/authy/fetch/012345678901234567890123456789012345678901234567890123456789'
        response = self.client.get(url,
                                   headers=headers)
        returned_data = response.json
        self.assertEqual(response.status_code, 400)
        self.assertEqual(returned_data.get("message"), "Supplied username too long")

    # -----------------------------------------------------------------------------

    def test_admin_return_role_details(self):

        users = addNormalUsers()
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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
        self.assertEqual(len(users), 8)
        admins = addAdminUsers()
        self.assertEqual(len(admins), 2)
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

    def test_admin_create_role_bad_json(self):
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
        response2 = self.client.post(url,
                                     json='yarp',
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 400)

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

    def test_admin_create_role_fail_on_schema(self):
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
                     'bad': 'juju',
                     'description': 'A description',
                     'level': 15 }
        response2 = self.client.post(url,
                                     json=new_role,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 400)

    # -----------------------------------------------------------------------------

    def test_admin_get_non_existent_user(self):
        users = addNormalUsers()
        admins = addAdminUsers()
        headers = { 'Content-type': 'application/json' }
        response = self.client.post('/authy/login',
                                    json=login_body(name="clivey",
                                                    passwd="password"),
                                    headers=headers)
        data = response.json
        self.assertEqual(response.status_code, 200)
        url = '/authy/user/'+str(uuid.uuid4())
        response2 = self.client.get(url,
                                     headers=headers_with_token(data['token']))
        self.assertEqual(response2.status_code, 404)

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

