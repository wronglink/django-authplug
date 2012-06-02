# -*- coding: utf-8 -*-
from contextlib import contextmanager
from copy import deepcopy
from django.contrib.auth.models import User
from django.test.client import RequestFactory
from django.test import TestCase
from authplug.client import sign
from authplug.middleware import PluggableAuthMiddleware
from authplug import middleware
from authplug.models import HashKey


class AuthPlugTestCase(TestCase):
    def setUp(self):
        self.good_user = User.objects.create_user('John', 'john_smith@example.com', 'password')
        self.bad_user = User.objects.create_user('313373 H4Xor', 'killer@mail.ru',  '12345')

        self.code = 'GOOD'
        self.salt = 'SALT'
        self.hk = HashKey.objects.create(user=self.good_user, code=self.code, salt=self.salt)
        self.params = {'param1': 'value1', 'param2': 'value2'}
        self.factory = RequestFactory()

    def fake_view(self, request):
        return getattr(request, 'user', None)

    def get_auth_header(self, code, signature, auth_scheme="AP"):
        auth_param = ":".join([code, signature]).encode('base64')
        return {'HTTP_AUTHORIZATION': "%s %s" % (auth_scheme, auth_param)}

    def get_user_as_response(self, request):
        plug_mw = PluggableAuthMiddleware()
        plug_mw.process_request(request=request)

        return self.fake_view(request)

    def tearDown(self):
        User.objects.all().delete()
        HashKey.objects.all().delete()

    def test_good_man_params_signature_ok(self):
        signature = sign(self.params, self.salt)
        self.assertTrue(self.hk.signature_ok(self.params, signature))

    def test_good_man_request_params_middleware(self):
        signature = sign(self.params, self.salt)
        self.params['code'] = self.code
        self.params['sign'] = signature

        params_copy = deepcopy(self.params)

        # middleware testing...
        request = self.factory.get('/some/private/view/', data=self.params)
        user_as_response = self.get_user_as_response(request)

        self.assertFalse(user_as_response is None, msg='fake_view returned None instead of good_user')
        self.assertEqual(user_as_response, self.good_user, msg='wrong user returned')
        # params were not hurt...
        self.assertEqual(params_copy, self.params, msg='params were likely hurt in the middleware')

    def test_bad_user_request_params_attempt(self):
        signature = sign(self.params, 'BAD SALT')
        self.params['code'] = self.code
        self.params['sign'] = signature

        # middleware testing...
        request = self.factory.get('/some/private/view/', data=self.params)
        user_as_response = self.get_user_as_response(request)

        self.assertTrue(user_as_response is None)  # no user is in request

    def test_good_man_http_header_middleware(self):
        signature = sign(self.params, self.salt)
        request = self.factory.get('/some/private/view/', self.params, **self.get_auth_header(self.code, signature))
        user_as_response = self.get_user_as_response(request)

        self.assertFalse(user_as_response is None, msg='fake_view returned None instead of good_user')
        self.assertEqual(user_as_response, self.good_user, msg='wrong user returned')

    def test_bad_user_http_header_attempt(self):
        signature = sign(self.params, 'BAD SALT')
        request = self.factory.get('/some/private/view/', self.params, **self.get_auth_header(self.code, signature))
        user_as_response = self.get_user_as_response(request)

        self.assertTrue(user_as_response is None)  # no user is in request

    def test_params_names_settings(self):
        with patch_settings('signn', 'codee'):
            signature = sign(self.params, self.salt)
            self.params['codee'] = self.code
            self.params['signn'] = signature

            request = self.factory.get('/some/private/view/', data=self.params)
            user_as_response = self.get_user_as_response(request)

            self.assertFalse(user_as_response is None, msg='fake_view returned None instead of good_user')
            self.assertEqual(user_as_response, self.good_user, msg='wrong user returned')


@contextmanager
def patch_settings(sign, code):
    old_sign = middleware.SIGNATURE_PARAMETER
    old_code = middleware.CODE_PARAMETER
    try:
        middleware.SIGNATURE_PARAMETER = sign
        middleware.CODE_PARAMETER = code
        yield
    finally:
        middleware.SIGNATURE_PARAMETER = old_sign
        middleware.CODE_PARAMETER = old_code

