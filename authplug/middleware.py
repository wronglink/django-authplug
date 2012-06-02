# -*- coding: utf-8 -*-
from django.contrib.auth import authenticate
from authplug.settings import SIGNATURE_PARAMETER, CODE_PARAMETER, AUTHORIZATION_SCHEME


class PluggableAuthMiddleware(object):
    def process_request(self, request):
        user = None

        # Try authenticate user via Authorization header
        auth_scheme, auth_param = self.get_http_auth_data(request)
        if auth_scheme == AUTHORIZATION_SCHEME:
            code, signature  = self.parse_credentials(auth_param)
            if code and signature:
                user = authenticate(code=code, params=request.REQUEST, signature=signature)

        # Try authenticate user via request parameters
        if not user and SIGNATURE_PARAMETER in request.REQUEST and CODE_PARAMETER in request.REQUEST:
            signature = request.REQUEST[SIGNATURE_PARAMETER]
            code = request.REQUEST[CODE_PARAMETER]

            params = dict(request.REQUEST)  # to copy, not have a link

            del params[SIGNATURE_PARAMETER]
            del params[CODE_PARAMETER]

            user = authenticate(code=code, params=params, signature=signature)

        if user:
            request.user = user

    def get_http_auth_data(self, request):
        """
        Returns (auth_scheme, auth_param) from HTTP Authorization header
        """
        if 'HTTP_AUTHORIZATION' in request.META:
            data = request.META['HTTP_AUTHORIZATION'].split(' ', 1)
            if len(data) == 2:
                return data

        return None, None

    def parse_credentials(self, auth_param):
        """
        Decodes and parses auth_param string and returns (code, signature) tuple
        """
        try:
            code, signature = auth_param.decode('base64').split(':')
            return code, signature
        except Exception:
            pass

        return None, None
