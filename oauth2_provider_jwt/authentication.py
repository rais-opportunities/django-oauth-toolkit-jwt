from typing import Any, Dict, Optional, Sequence

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.utils.encoding import smart_str
import jwt
from rest_framework import exceptions
from rest_framework.authentication import (
    BaseAuthentication, get_authorization_header
)

from .utils import decode_jwt, get_issuer_settings, JWKNotFoundError


class JwtToken(dict):
    """
    Mimics the structure of `AbstractAccessToken` so you can use standard
    Django Oauth Toolkit permissions like `TokenHasScope`.
    """
    def __init__(self, payload):
        super(JwtToken, self).__init__(**payload)

    def __getattr__(self, item):
        return self[item]

    def is_valid(self, scopes: Optional[Sequence[str]] = None) -> bool:
        """Check if the access token is valid.

        Args:
            scopes: The scopes to check or None
        """
        return not self.is_expired() and self.allow_scopes(scopes)

    def is_expired(self) -> bool:
        """Check token expiration with timezone awareness."""
        # Token expiration is checked when validating the token signature
        # during the request.
        return False

    def allow_scopes(self, scopes: Optional[Sequence[str]]) -> bool:
        """Check if the token allows the provided scopes.

        Args:
            scopes: The scopes to check
        """
        if not scopes:
            return True

        provided_scopes = set(self.scope.split())
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)


class JWTAuthentication(BaseAuthentication):
    """
    Token based authentication using the JSON Web Token standard.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:

        Authorization: JWT eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication.  Otherwise returns `None`.
        """
        jwt_value = self._get_jwt_value(request)
        if jwt_value is None:
            return None

        try:
            payload = decode_jwt(jwt_value)
        except jwt.ExpiredSignatureError:
            msg = 'Signature has expired.'
            raise exceptions.AuthenticationFailed(msg)
        except jwt.DecodeError:
            msg = 'Error decoding signature.'
            raise exceptions.AuthenticationFailed(msg)
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed()
        except JWKNotFoundError:
            msg = 'Key not found.'
            raise exceptions.AuthenticationFailed(msg)

        self._add_session_details(request, payload)

        user = self.authenticate_credentials(payload)
        return user, JwtToken(payload)

    @staticmethod
    def authenticate_credentials(payload):
        """Returns an active user that matches the payload's user id and email.
        """
        if settings.OAUTH2_PROVIDER.get('JWT_AUTH_DISABLED', False):
            return AnonymousUser()

        default_issuer = settings.OAUTH2_PROVIDER.get(
            'JWT_DEFAULT_ISSUER', None)
        if 'iss' in payload:
            issuer = payload['iss']
        elif default_issuer is not None:
            issuer = default_issuer
        else:
            raise exceptions.AuthenticationFailed(
                'Unable to determine issuer. Token missing iss claim')

        try:
            iss_config: Dict[str, Any] = get_issuer_settings(issuer)
        except ImproperlyConfigured:
            raise exceptions.AuthenticationFailed(
                f'Received token for unknown issuer: {issuer}')

        try:
            id_attribute_map: Dict[str, Any] = iss_config['id_attribute_map']
        except KeyError:
            raise KeyError(f"Missing id_attribute_map for issuer: {issuer}")

        if 'attribute' not in id_attribute_map \
           or 'claim' not in id_attribute_map:
            raise ValueError(
                f'Misconfigured id_attribute_map for issuer: {issuer}')

        User = get_user_model()
        claim_field_name = id_attribute_map['claim']
        lookup_field_name = id_attribute_map['attribute']

        lookup_value = payload.get(claim_field_name)

        if not lookup_field_name:
            raise ValueError(
                'Blank or unknown id_attribute_map attribute for issuer: '
                f'{issuer}')

        if not lookup_value:
            raise exceptions.AuthenticationFailed(
                f'JWT missing expected claim: {claim_field_name} '
                f'(issuer: {issuer})')

        try:
            kwargs = {
                lookup_field_name: lookup_value
            }
            user = User.objects.get(**kwargs)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('User not found')

        if not user.is_active:
            raise exceptions.AuthenticationFailed('User account is disabled.')

        return user

    @staticmethod
    def _get_jwt_value(request) -> Optional[str]:
        auth = get_authorization_header(request).split()
        auth_header_prefix = settings.OAUTH2_PROVIDER.get(
            'JWT_AUTH_HEADER_PREFIX', 'JWT')

        if not auth:
            auth_cookie_name = settings.OAUTH2_PROVIDER.get(
                'JWT_AUTH_COOKIE', None)
            if auth_cookie_name:
                return request.COOKIES.get(auth_cookie_name)
            return None

        if smart_str(auth[0]) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = 'Invalid Authorization header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = ('Invalid Authorization header. Credentials string '
                   'should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        jwt_value = auth[1]
        if isinstance(jwt_value, bytes):
            jwt_value = jwt_value.decode('utf-8')
        return jwt_value

    @staticmethod
    def _add_session_details(request, payload):
        """Adds to the session payload details so they can be used anytime."""
        try:
            items = payload.iteritems()
        except AttributeError:  # python 3.6
            items = payload.items()
        for k, v in items:
            if k not in ('iat', 'exp'):
                request.session['jwt_{}'.format(k)] = v

    def authenticate_header(self, _request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        auth_header_prefix = settings.OAUTH2_PROVIDER.get(
            'JWT_AUTH_HEADER_PREFIX', 'JWT')
        return '{0} realm="{1}"'.format(auth_header_prefix,
                                        self.www_authenticate_realm)
