import base64
from datetime import datetime, timedelta
import json
from logging import getLogger
from typing import Any, Dict, Mapping, Optional, Union

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
import jwt

from .types import IssuerSettingsDict

logger = getLogger(__name__)


class JWKNotFoundError(Exception):
    pass


def generate_payload(
        issuer: str,
        expires_in: int,
        **extra_data
) -> Dict[str, Union[str, int]]:
    """Generate a base JWT payload.

    Args:
        issuer: identifies the principal that issued the token.
        expires_in: number of seconds that the token will be valid.
        extra_data: extra data to be added to the payload.

    Returns:
        Mapping containing issuer, expiration, issued at timestamp, and all
        user provided additional keyword arguments.
    """
    now = datetime.utcnow()
    issued_at = now
    expiration = now + timedelta(seconds=expires_in)

    payload = {
        'iss': issuer,
        'exp': expiration,
        'iat': issued_at,
    }

    if extra_data:
        payload.update(**extra_data)

    return payload


def encode_jwt(payload: Mapping, issuer: Optional[str] = None,
               headers: Optional[Dict[str, Union[str, int]]] = None) -> str:
    """Sign and encode the provided ``payload`` as ``issuer``.

    Args:
        payload: the payload of the JWT.
        issuer: the issuer to use when signing the token. If not provided this
            value is looked up using the ``iss`` claim and will fall back to
            the ``JWT_DEFAULT_ISSUER`` setting.
        headers: additional values to include in header.

    Raises:
        ValueError: Unable to determine the issuer to use for the JWT.
        ImproperlyConfigured: Unable to determine settings for the issuer.

    Returns:
        A signed JWT.
    """
    if not issuer:
        default_issuer: Optional[str] = settings.OAUTH2_PROVIDER.get(
            'JWT_DEFAULT_ISSUER', None)
        if 'iss' in payload:
            iss: str = payload['iss']
        elif default_issuer is not None:
            iss = default_issuer
        else:
            raise ValueError(
                'Unable to determine issuer. Token missing iss claim')
    else:
        iss = issuer

    if headers is None:
        headers = {}

    # May raise ImproperlyConfigured
    iss_config: Dict[str, Any] = get_issuer_settings(iss)

    algorithm: str = iss_config.get('encoding_algorithm', 'RS256')

    private_key_func: Optional[str] = iss_config.get('private_key_func', None)
    private_key: Optional[str] = iss_config.get('private_key', None)
    key_id: Optional[str] = None

    if private_key_func and private_key:
        logger.warning(
            'Both private_key_func and private_key are defined for issuer: '
            f'{iss}. Remove the value for private_key. Ignoring for now.')
        private_key = None
    elif private_key_func is None and private_key is None:
        raise ImproperlyConfigured(
            f'Missing private_key_func or private_key for issuer {iss}')

    if private_key_func:
        key_fn = import_string(private_key_func)
        key_id, private_key = key_fn(iss)
        if not private_key:
            # Differentiate function failure from a misconfigured private_key
            # setting
            raise JWKNotFoundError(
                f'private_key_func: {private_key_func} returned an empty key '
                f'for issuer: {iss}')

    if not private_key:
        raise ImproperlyConfigured(
            f'private_key must not be blank for issuer {iss}')

    if key_id is not None:
        headers['kid'] = key_id

    encoded = jwt.encode(
        payload, private_key, algorithm=algorithm, headers=headers)

    return encoded.decode('utf-8')


def decode_jwt(token: str, issuer: Optional[str] = None) -> Dict[str, Any]:
    """Validate and decode the provided ``jwt_value``.

    Args:
        token: The JWT to decode
        issuer: the issuer's key to use from when validating. If this is
            None then the value from the ``iss`` claim will be used.

    Raises:
        jwt.InvalidTokenError: The provided token is not a valid JWT.
        jwt.InvalidIssuerError: Unknown issuer provided. Define issuer in
            settings.
        ImproperlyConfiguredError: Unable to find issuer's key.

    Return:
        The decoded payload from the JWT.
    """
    try:
        # headers, payload, signature
        b64headers, b64payload, _ = token.split(".")
    except ValueError:
        raise jwt.InvalidTokenError()

    # add padding
    b64payload += '=' * (-len(b64payload) % 4)
    b64headers += '=' * (-len(b64headers) % 4)

    payload = json.loads(base64.b64decode(b64payload).decode("utf-8"))
    headers = json.loads(base64.b64decode(b64headers).decode("utf-8"))

    if not issuer:
        if 'iss' in payload:
            iss: str = payload['iss']
        else:
            raise ValueError(
                'Unable to determine issuer. Token missing iss claim')
    else:
        iss = issuer

    try:
        iss_config: Dict[str, Any] = get_issuer_settings(iss)
    except ImproperlyConfigured:
        raise jwt.InvalidIssuerError(f'Unknown issuer {issuer}')

    public_key_func: Optional[str] = iss_config.get('public_key_func', None)
    public_key: Optional[str] = iss_config.get('public_key', None)
    algorithms = iss_config.get('validation_algorithms', ['HS256', 'RS256'])

    key_id = headers.get('kid', None)

    if public_key_func and public_key:
        logger.warning(
            'Both public_key_func and public_key are defined for issuer: '
            '{iss}. Remove the value for public_key. Ignoring for now.')
        public_key = None
    elif public_key_func is None and public_key is None:
        raise ImproperlyConfigured(
            f'Missing public_key_func or public_key for issuer {iss}')

    if public_key_func:
        key_fn = import_string(public_key_func)
        public_key = key_fn(iss, key_id)
        if not public_key:
            # Differentiate function failure from a misconfigured public_key
            # setting
            raise JWKNotFoundError(
                f'public_key_func {public_key_func} returned an empty key '
                f'for key_id: {key_id} and issuer: {iss}')

    if not public_key:
        raise ImproperlyConfigured(
            f'public_key must not be blank for issuer {iss}')

    decoded = jwt.decode(
        token,
        public_key,
        algorithms=algorithms,
        options={
            'verify_aud': False,
        })
    return decoded


def get_issuer_settings(
    issuer: str
) -> IssuerSettingsDict:
    """Retrieve the settings defined for the provided issuer.

    Args:
        issuer: The issuer to pull settings for

    Raises:
        ImproperlyConfigured: The settings for the requested issuer were not
            found.

    Returns:
        The configuration for the issuer defined in settings.py.
    """
    issuers_config = getattr(settings, 'OAUTH2_PROVIDER', {})\
        .get('JWT_ISSUERS', {})

    try:
        return issuers_config[issuer]
    except KeyError:
        raise ImproperlyConfigured(
            f'Settings for {issuer} were not found in '
            "OAUTH2_PROVIDER['JWT_ISSUERS']")
