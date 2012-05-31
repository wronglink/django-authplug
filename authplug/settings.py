# -*- coding: utf-8 -*-
from django.conf import settings

SIGNATURE_PARAMETER = getattr(settings, 'AUTHPLUG_SIGNATURE_PARAMETER', 'sign')
CODE_PARAMETER = getattr(settings, 'AUTHPLUG_CODE_PARAMETER', 'code')

AUTHORIZATION_SCHEME = getattr(settings, 'AUTHPLUG_AUTHORIZATION_SCHEME', 'AP')
