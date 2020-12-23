import base64
from datetime import datetime, timedelta
import json
from typing import Any, Dict, Mapping, Optional, Union

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import jwt

from .types import IssuerSettingsDict


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
               headers: Optional[Mapping] = None) -> str:
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

    # May raise ImproperlyConfigured
    iss_config: Dict[str, Any] = get_issuer_settings(iss)

    algorithm: str = iss_config.get('encoding_algorithm', 'RS256')

    try:
        private_key: str = iss_config['private_key']
    except KeyError:
        raise ImproperlyConfigured(
            f"Missing private_key for issuer {iss}")

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
        _, payload_enc, _ = token.split(".")
    except ValueError:
        raise jwt.InvalidTokenError()

    payload_enc += '=' * (-len(payload_enc) % 4)  # add padding
    payload = json.loads(base64.b64decode(payload_enc).decode("utf-8"))

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

    algorithms = iss_config.get('validation_algorithms', ['HS256', 'RS256'])

    try:
        public_key: str = iss_config['public_key']
    except KeyError:
        raise ImproperlyConfigured(f'Missing public key for {issuer}')

    decoded = jwt.decode(token, public_key, algorithms=algorithms)
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
