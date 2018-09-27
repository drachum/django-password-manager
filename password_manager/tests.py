from django.test import TestCase
from django.apps import apps
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase
from password_manager.models import Password, TemporaryKey

client = APIClient()
User = apps.get_model('auth', 'User')


class MininumTestSetup(APITestCase):
    """
    This makes tests possible by adding on the database all objects we need.
    NOTE: it is done here and it is not using migrations like solutions
    because at the time it was built we were using django 1.8. This django
    version has a problem with slow migrations (can take dozens of MINUTES) to
    run and we do not want to wait this time each time we execute a test.
    """
    def setUp(self):
        # basic user to authenticate
        self.user_pass = 'password'
        self.user = User.objects.create_user(username='test')
        self.user.set_password(self.user_pass)
        self.user.is_active = True
        self.user.is_superuser = True
        self.user.save()

    def tearDown(self):
        self.user.delete()

    def _create_temporary_key(self):
        client.force_authenticate(user=self.user)
        response = client.post(
            '/user/{0}/temporary_key/'.format(self.user.id),
            {'password': self.user_pass},
            format='json'
        )
        self.assertEqual(response.status_code, 200,
                         'Temporary key creation should be ok')
        return response.data['temporary_key']


class TemporaryKeyTest(MininumTestSetup):
    """
    Tests all aspects related to the following endpoint:

        /temporary_key/ [POST]

    It is the endpoint which generates temporary keys that allows users to call
    all other methods on logins app.
    """
    def test_temporary_key_creation_ok(self):
        from password_manager.encrypt import DefaultCipher
        from base64 import b16decode

        client_temporary_key = self._create_temporary_key()
        self.assertEqual(len(client_temporary_key), 64,
                         'Key should have 64 bytes')

        # checking our encryption flow
        decoded_client_temporary_key = b16decode(client_temporary_key)
        db_encrypted_password = TemporaryKey.objects.get().encrypted_password

        cipher = DefaultCipher(decoded_client_temporary_key)
        decrypted_password = cipher.decrypt(db_encrypted_password)
        self.assertEqual(decrypted_password, self.user_pass,
                         'TemporaryKey Encryption flow is not working')

    def test_temporary_key_authentication_ok(self):
        client_temporary_key = self._create_temporary_key()
        response = client.get(
            '/user/{0}/password/'.format(self.user.id),
            HTTP_AUTHORIZATION=client_temporary_key,
        )
        self.assertEqual(response.status_code, 200,
                         'Temporary key authentication not working')

    def test_temporary_key_invalid_user(self):
        response = client.post(
            '/user/10921928309231/temporary_key/',
            {'password': 'password'},
            format='json'
        )
        self.assertEqual(response.status_code, 400, 'Invalid user passing')
        self.assertEqual(response.data, 'Invalid user')

    def test_temporary_key_invalid_temporary_key(self):
        client.force_authenticate(user=self.user)
        response = client.get(
            '/user/{0}/password/'.format(self.user.id),
            HTTP_AUTHORIZATION='0' * 64,
        )
        self.assertEqual(response.status_code, 403,
                         'Invalid temporary key passing')
        self.assertEqual(response.content, b'User has no temporary key created')
    def test_temporary_key_expired(self):
        datetime_before_getting_key = (timezone.now() -
                                       timezone.timedelta(days=1))

        client_temporary_key = self._create_temporary_key()

        # now we make temporary key forcefully invalid!
        db_temporary_key = TemporaryKey.objects.get()
        db_temporary_key.expires_at = datetime_before_getting_key
        db_temporary_key.save()

        response = client.get(
            '/user/{0}/password/'.format(self.user.id),
            HTTP_AUTHORIZATION=client_temporary_key,
        )
        self.assertEqual(response.status_code, 403,
                         'Invalid temporary expiration not working')
        self.assertEqual(response.content, b'Temporary key is expired')


class PasswordListTest(MininumTestSetup):
    """
    Tests all aspects related to the following endpoint:

        /user/<user_id>/password/ [GET]

    This endpoints return all passwords info for each user (with no pass
    into them).
    """
    def setUp(self):
        super().setUp()

        self.client_temporary_key = self._create_temporary_key()

        # create some passwords to simplify our tests
        pass1 = Password.objects.create(
            user=self.user,
            username='test1',
            organization='test1',
            url='http://test.com',
        )
        pass2 = Password.objects.create(
            user=self.user,
            username='test2',
            organization='test2',
            url='http://test.com',
        )
        self.passwords = [pass1, pass2]

    def test_password_list_assure_mandatory_authentication(self):
        response = client.get(
            '/user/{0}/password/'.format(self.user.id),
            HTTP_AUTHORIZATION='0' * 64,
        )
        self.assertEqual(response.status_code, 403,
                         'Temporary key autorization must block this call')

    def test_password_list_ok(self):
        response = client.get(
            '/user/{0}/password/'.format(self.user.id),
            HTTP_AUTHORIZATION=self.client_temporary_key,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 2, 'Should return 2 passwords')

        password_required_attributes = sorted(
            ['id', 'username', 'organization', 'url']
        )
        password_returned_item = response.data[0]

        self.assertEqual(
            password_required_attributes,
            sorted(password_returned_item.keys()),
            'Password must have {0} attributes'.format(','.join(
                password_required_attributes))
        )

    def test_password_list_not_listing_deleted_ones(self):
        new_deleted_pass = Password.objects.create(
            user=self.user,
            username='test2',
            organization='test2',
            url='http://test.com',
            deleted=True
        )
        self.assertEqual(Password.objects.count(), 3,
                         'Should have 3 stored passwords as I added 1')

        response = client.get(
            '/user/{0}/password/'.format(self.user.id),
            HTTP_AUTHORIZATION=self.client_temporary_key,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 2,
                         'Should not return the deleted password')

        new_deleted_pass.delete()

    def tearDown(self):
        super().tearDown()
        for p in self.passwords:
            p.delete()


class PasswordAddTest(MininumTestSetup):
    """
    Tests all aspects related to the following endpoint:

        /user/<user_id>/password/ [POST]

    This endpoint creates a password for an user.
    """
    def setUp(self):
        super().setUp()

        self.client_temporary_key = self._create_temporary_key()

    def _call_add_method(self, data, HTTP_AUTHORIZATION=None):
        client.force_authenticate(user=self.user)

        if HTTP_AUTHORIZATION is None:
            HTTP_AUTHORIZATION = self.client_temporary_key

        return client.post(
            '/user/{0}/password/'.format(self.user.id),
            data,
            HTTP_AUTHORIZATION=HTTP_AUTHORIZATION,
            format='json'
        )

    def test_password_add_assure_mandatory_authentication(self):
        response = self._call_add_method({}, HTTP_AUTHORIZATION='0' * 64)
        self.assertEqual(response.status_code, 403,
                         'Temporary key autorization must block this call')

    def test_password_add_ok(self):
        password_object_json = {
            'username': 'addtest',
            'organization': 'addtest',
            'url': 'http://test.com',
            'password': 'addtestpass'
        }
        response = self._call_add_method(password_object_json)
        self.assertEqual(response.status_code, 200)
        password_returned = response.data

        # check minimum attributes that must be returned
        password_required_attributes = ['id', 'username', 'organization', 'url']

        for attr in password_required_attributes:
            self.assertTrue(
                attr in password_returned,
                'Password returned should have attribute: {0}'.format(attr)
            )

        # check the content created
        self.assertEqual(
            password_returned['username'], password_object_json['username']
        )
        self.assertEqual(
            password_returned['organization'],
            password_object_json['organization']
        )
        self.assertEqual(
            password_returned['url'], password_object_json['url']
        )
        # assure not storing plain text passwords!
        db_password = Password.objects.get()
        self.assertNotEqual(
            db_password.encrypted_password,
            password_object_json['password']
        )

    def test_password_add_validation(self):
        response = self._call_add_method({})
        self.assertEqual(response.status_code, 400,
                         'Should not accept empty password creation')

        response = self._call_add_method({'password': 'test'})
        self.assertEqual(response.status_code, 400,
                         'Should not accept empty password creation')

        response = self._call_add_method({
            'password': 'test',
            'username': 'test',
            'organization': 'test',
        })
        self.assertEqual(response.status_code, 200,
                         'Should accept with this three main parameters')

        response = self._call_add_method({
            'password': 'test',
            'username': 'test',
            'organization': 'test',
        })
        self.assertEqual(response.status_code, 200,
                         'Should accept with three main parameters')

        Password.objects.all().delete()


class PasswordDeleteTest(MininumTestSetup):
    """
    Tests all aspects related to the following endpoint:

        /user/<user_id>/password/<password_id>/ [DELETE]

    This endpoint creates deletes a password of an user. Note that deletion to
    us is the same as changing a flag on database. We NEVER lost data.
    """
    def test_password_add_assure_mandatory_authentication(self):
        # creates a password and delete it, checking for the expected behavior
        db_password = Password.objects.create(
            user=self.user,
            username='test1',
            organization='test1',
            url='http://test.com',
        )

        response = client.delete(
            '/user/{0}/password/{1}/'.format(self.user.id,
                                                    db_password.id),
        )
        self.assertEqual(response.status_code, 403,
                         'Temporary key autorization must block this call')
        db_password.delete()

    def test_password_delete_ok(self):
        client_temporary_key = self._create_temporary_key()

        # creates a password and delete it, checking for the expected behavior
        db_password = Password.objects.create(
            user=self.user,
            username='test1',
            organization='test1',
            url='http://test.com',
        )
        self.assertEqual(db_password.deleted, False,
                         'It should start with deleted marked as False')

        response = client.delete(
            '/user/{0}/password/{1}/'.format(self.user.id,
                                                    db_password.id),
            HTTP_AUTHORIZATION=client_temporary_key,
        )
        db_password.refresh_from_db()
        self.assertEqual(response.status_code, 204)
        self.assertEqual(db_password.deleted, True,
                         'It have to mark deleted flag as True')
        db_password.delete()


class PasswordGetTest(MininumTestSetup):
    """
    Tests all aspects related to the following endpoint:

        /user/<user_id>/password/<password_id>/ [GET]

    This endpoint get all information from an user password, INCLUDING the
    PASSWORD itself. So that, it uses cipher decryption to make its work!
    """
    def test_password_get_assure_mandatory_authentication(self):
        db_password = Password.objects.create(
            user=self.user,
            username='test1',
            organization='test1',
            url='http://test.com',
        )
        response = client.get(
            '/user/{0}/password/{1}/'.format(self.user.id,
                                                    db_password.id),
        )
        self.assertEqual(response.status_code, 403,
                         'Temporary key autorization must block this call')
        db_password.delete()

    def test_password_get_ok(self):
        client_temporary_key = self._create_temporary_key()

        # creating an encrypted password
        password_object_json = {
            'username': 'addtest',
            'organization': 'addtest',
            'url': 'http://test.com',
            'password': 'addtestpass'
        }

        response = client.post(
            '/user/{0}/password/'.format(self.user.id),
            password_object_json,
            HTTP_AUTHORIZATION=client_temporary_key,
            format='json'
        )
        password_created = response.data
        self.assertEqual(response.status_code, 200,
                         'Password creation should be ok')

        response = client.get(
            '/user/{0}/password/{1}/'.format(self.user.id,
                                                    password_created['id']),
            HTTP_AUTHORIZATION=client_temporary_key,
        )
        password_returned = response.data

        # check the content created x got by get method
        self.assertEqual(
            password_returned['username'], password_object_json['username']
        )
        self.assertEqual(
            password_returned['organization'],
            password_object_json['organization']
        )
        self.assertEqual(
            password_returned['url'], password_object_json['url']
        )
        self.assertEqual(
            password_returned['password'], password_object_json['password']
        )
        Password.objects.all().delete()


class PasswordEditTest(object):
    """
    Tests all aspects related to the following endpoint:

        /user/<user_id>/password/<password_id>/ [PUT]

    This endpoint must allow user change all information about an user password.
    """
    def setUp(self):
        super().setUp()
        self.client_temporary_key = self._create_temporary_key()

    def _call_edit_method(self, password_id, data, HTTP_AUTHORIZATION=None):
        if HTTP_AUTHORIZATION is None:
            HTTP_AUTHORIZATION = self.client_temporary_key

        return client.put(
            '/user/{0}/password/{1}'.format(self.user.id, password_id),
            data,
            HTTP_AUTHORIZATION=HTTP_AUTHORIZATION,
            format='json'
        )

    def test_password_edit_assure_mandatory_authentication(self):
        db_password = Password.objects.create(
            user=self.user,
            username='test1',
            organization='test1',
            url='http://test.com',
        )
        response = self._call_edit_method(
            db_password.id,
            {},
            HTTP_AUTHORIZATION='0' * 64
        )
        self.assertEqual(response.status_code, 403,
                         'Temporary key autorization must block this call')
        db_password.delete()

    def test_password_edit_ok(self):
        db_password = Password.objects.create(
            user=self.user,
            username='test1',
            organization='test1',
            url='http://test.com',
        )
        password_edit_object_json = {
            'username': 'addteste',
            'organization': 'addteste',
            'url': 'http://test.come',
            'password': 'addtestpasse'
        }
        response = self._call_edit_method(db_password.id, password_edit_object_json)
        self.assertEqual(response.status_code, 200)
        password_returned = response.data

        # check minimum attributes that must be returned
        password_required_attributes = ['id', 'username', 'organization', 'url']

        for attr in password_required_attributes:
            self.assertTrue(
                attr in password_returned,
                'Password returned should have attribute: {0}'.format(attr)
            )

        # check the content created
        self.assertEqual(
            password_returned['username'],
            password_edit_object_json['username']
        )
        self.assertEqual(
            password_returned['organization'],
            password_edit_object_json['organization']
        )
        self.assertEqual(
            password_returned['url'], password_edit_object_json['url']
        )

        # assure that password was changed!
        db_password = Password.objects.get()
        self.assertNotEqual(
            db_password.encrypted_password,
            password_edit_object_json['password'],
            'Password was not changed'
        )

        # assure not storing plain text passwords!
        db_password = Password.objects.get()
        self.assertNotEqual(
            db_password.encrypted_password,
            password_edit_object_json['password'],
            'Passwword is stored in plain text'
        )

    def test_password_edit_validation(self):
        db_password = Password.objects.create(
            user=self.user,
            username='test1',
            organization='test1',
            url='http://test.com',

        )
        response = self._call_edit_method(190283091283, {})
        self.assertEqual(response.status_code, 400,
                         'Should not accept invalid password_id')

        response = self._call_edit_method(db_password.id, {})
        self.assertEqual(response.status_code, 400,
                         'Should not accept empty password edit')

        response = self._call_edit_method(db_password.id, {
            'id': db_password.id,
            'username': 't' * 300
        })
        self.assertEqual(response.status_code, 400,
                         'Allowed invalid big username')

        response = self._call_edit_method(db_password.id, {
            'organization': 't' * 300
        })
        self.assertEqual(response.status_code, 400,
                         'Allowed invalid big organization')

        db_password.delete()


class PasswordCompleteFlowTests(MininumTestSetup):
    """
    It will execute a simple and complete flow that might be done for a client.
        1. Add a pass
        2. List all of them
        3. Data from one
        4. Edit this one
        5. Delete it!
    """
    def test_password_edit_ok(self):
        from copy import deepcopy

        client_temporary_key = self._create_temporary_key()

        self.assertFalse(Password.objects.all(), 'Password table must be empty')
        # create
        data_create = {
            'username': 'test',
            'organization': 'test',
            'password': 'test'
        }
        response = client.post(
            '/user/{0}/password/'.format(self.user.id),
            data_create,
            HTTP_AUTHORIZATION=client_temporary_key,
            format='json'
        )
        password_created = response.data

        # list
        response = client.get(
            '/user/{0}/password/'.format(self.user.id),
            HTTP_AUTHORIZATION=client_temporary_key,
        )
        passwords_listed = response.data
        self.assertTrue(passwords_listed, 'Password was not added')

        # get
        response = client.get(
            '/user/{0}/password/{1}'.format(self.user.id,
                                                   password_created['id']),
            HTTP_AUTHORIZATION=client_temporary_key,
        )
        password_got = response.data
        self.assertEqual(password_created['id'], password_got['id'])

        # edit
        changed_username = 'test1'
        data_edit = deepcopy(data_create)
        data_edit['username'] = changed_username

        response = client.put(
            '/user/{0}/password/{1}'.format(self.user.id,
                                                   password_got['id']),
            data_edit,
            HTTP_AUTHORIZATION=client_temporary_key,
            format='json'
        )
        self.assertEqual(Password.objects.get().username, changed_username,
                         'Edit method is not working!')

        # delete
        response = client.delete(
            '/user/{0}/password/{1}'.format(self.user.id,
                                                   password_created['id']),
            HTTP_AUTHORIZATION=client_temporary_key,
            format='json'
        )
