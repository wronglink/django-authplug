# -*- coding: utf-8 -*-
from django.contrib.auth import authenticate
from authplug.settings import SIGNATURE_PARAMETER, CODE_PARAMETER


class PluggableAuthMiddleware(object):
    def process_request(self, request):
        if SIGNATURE_PARAMETER not in request.REQUEST or CODE_PARAMETER not in request.REQUEST:
            return

        signature = request.REQUEST[SIGNATURE_PARAMETER]
        code = request.REQUEST[CODE_PARAMETER]

        params = dict(request.REQUEST)  # to copy, not have a link

        del params[SIGNATURE_PARAMETER]
        del params[CODE_PARAMETER]

        user = authenticate(code=code, params=params, signature=signature)
        if user:
            request.user = user
