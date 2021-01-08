import base64
from copy import deepcopy
from datetime import datetime, timedelta
import json
from unittest.mock import patch
from unittest import TestCase as PythonTestCase

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings
import jwt
from oauth2_provider_jwt import utils

issuer_special_chars = 'https://api.service.cloud'
privkey = settings.OAUTH2_PROVIDER['JWT_ISSUERS']['issuer']['private_key']
pubkey = settings.OAUTH2_PROVIDER['JWT_ISSUERS']['issuer']['public_key']


def private_key_func(issuer):  # noqa
    return 'a3ecdb9', privkey

def public_key_func(issuer, kid):  # noqa
    return pubkey


class GeneratePayloadTest(PythonTestCase):
    def _get_payload_args(self):
        issuer = 'activityapi'
        expires_in = 36000
        return issuer, expires_in

    @patch('oauth2_provider_jwt.utils.datetime')
    def test_generate_payload_no_extra_data(self, mock_datetime):
        now = datetime.utcnow()
        mock_datetime.utcnow.return_value = now
        issuer, expires_in = self._get_payload_args()
        expiration = now + timedelta(seconds=expires_in)

        self.assertEqual(
            utils.generate_payload(issuer, expires_in),
            {
                'iss': issuer,
                'exp': expiration,
                'iat': now,
            }
        )

    @patch('oauth2_provider_jwt.utils.datetime')
    def test_generate_payload_with_extra_data(self, mock_datetime):
        now = datetime.utcnow()
        mock_datetime.utcnow.return_value = now

        issuer, expires_in = self._get_payload_args()
        expiration = now + timedelta(seconds=expires_in)

        extra_data = {
            'usr': 'some_usr',
            'org': 'some_org',
            'sub': 'subject',
        }

        self.assertEqual(
            utils.generate_payload(issuer, expires_in, **extra_data),
            {
                'iss': issuer,
                'exp': expiration,
                'iat': now,
                'sub': 'subject',
                'usr': 'some_usr',
                'org': 'some_org',
            }
        )


class EncodeJWTTest(PythonTestCase):
    def _get_payload(self):
        now = datetime.utcnow()
        return {
            'iss': 'issuer',
            'exp': now + timedelta(seconds=10),
            'iat': now,
            'sub': 'subject',
            'usr': 'some_usr',
            'org': 'some_org',
        }

    def test_no_private_keys_defined(self):
        # Validate that an error is thrown when neither private_key_func or
        # private_key are defined.
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        if 'private_key' in settings_copy['JWT_ISSUERS']['issuer']:
            del settings_copy['JWT_ISSUERS']['issuer']['private_key']
        if 'private_key_func' in settings_copy['JWT_ISSUERS']['issuer']:
            del settings_copy['JWT_ISSUERS']['issuer']['private_key_func']

        with override_settings(OAUTH2_PROVIDER=settings_copy):
            payload = self._get_payload()
            self.assertRaises(ImproperlyConfigured,
                              utils.encode_jwt, payload)

    @patch('oauth2_provider_jwt.utils.jwt.encode')
    def test_favor_private_key_func(self, jwtencode_mock):
        # Validate that private_key_func is preferred when both
        # private_key_func and private_key are defined.
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        settings_copy['JWT_ISSUERS']['issuer']['private_key'] = 'dontuse'
        settings_copy['JWT_ISSUERS']['issuer']['private_key_func'] = \
            'tests.test_utils.private_key_func'
        keyfn_retval = private_key_func('issuer')

        payload = self._get_payload()
        with patch('tests.test_utils.private_key_func') as keyfn_mock:
            keyfn_mock.return_value = keyfn_retval
            with override_settings(OAUTH2_PROVIDER=settings_copy):
                # This will raise a ValueError about not being able to
                # deserialize data if the string is used instead of the
                # function. (i.e. can't deserialize the string as a valid PEM
                # encoded key)
                utils.encode_jwt(payload)
            keyfn_mock.assert_called()
        jwtencode_mock.assert_called_with(
            payload, keyfn_retval[1], algorithm='RS256',
            headers={'kid': keyfn_retval[0]})

    def test_none_private_key(self):
        # Validate that a private_key of None causes an error.
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        settings_copy['JWT_ISSUERS']['issuer']['private_key'] = None
        settings_copy['JWT_ISSUERS']['issuer']['private_key_func'] = None

        with override_settings(OAUTH2_PROVIDER=settings_copy):
            self.assertRaises(
                ImproperlyConfigured, utils.encode_jwt, self._get_payload())

    def test_blank_private_key(self):
        # Validate that a blank private key causes an error.
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        settings_copy['JWT_ISSUERS']['issuer']['private_key'] = ''
        if 'private_key_func' in settings_copy['JWT_ISSUERS']['issuer']:
            del settings_copy['JWT_ISSUERS']['issuer']['private_key_func']

        with override_settings(OAUTH2_PROVIDER=settings_copy):
            self.assertRaises(
                ImproperlyConfigured, utils.encode_jwt, self._get_payload())

    def test_private_key_func(self):
        # Validate that private_key_func is called.
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        del settings_copy['JWT_ISSUERS']['issuer']['private_key']
        settings_copy['JWT_ISSUERS']['issuer']['private_key_func'] = \
            'tests.test_utils.private_key_func'

        with override_settings(OAUTH2_PROVIDER=settings_copy):
            token = utils.encode_jwt(self._get_payload())

        # Some value should be returned without error.
        self.assertEqual(type(token), str)

    def test_include_kid_header(self):
        # Validate that the kid header is included when it is known.
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        del settings_copy['JWT_ISSUERS']['issuer']['private_key']
        settings_copy['JWT_ISSUERS']['issuer']['private_key_func'] = \
            'tests.test_utils.private_key_func'
        keyid, _ = private_key_func('issuer')

        with override_settings(OAUTH2_PROVIDER=settings_copy):
            token = utils.encode_jwt(self._get_payload())
        b64header, _, _ = token.split('.')
        b64header += '=' * (-len(b64header) % 4)
        header = json.loads(base64.urlsafe_b64decode(b64header))

        self.assertIn('kid', header)
        self.assertEqual(header['kid'], keyid)

    def test_omit_kid_header(self):
        # Validate that the kid header is omitted when it is None.
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        del settings_copy['JWT_ISSUERS']['issuer']['private_key']
        settings_copy['JWT_ISSUERS']['issuer']['private_key_func'] = \
            'tests.test_utils.private_key_func'

        with patch('tests.test_utils.private_key_func') as mock_keyfn:
            mock_keyfn.return_value = None, privkey
            with override_settings(OAUTH2_PROVIDER=settings_copy):
                token = utils.encode_jwt(self._get_payload())

        b64header, _, _ = token.split('.')
        b64header += '=' * (-len(b64header) % 4)
        header = json.loads(base64.urlsafe_b64decode(b64header))

        self.assertNotIn('kid', header)

    def test_encode_jwt_rs256(self):
        payload_in = self._get_payload()
        encoded = utils.encode_jwt(payload_in)
        self.assertEqual(type(encoded), str)
        headers, payload, _ = encoded.split(".")
        self.assertDictEqual(
            json.loads(base64.b64decode(headers)),
            {"typ": "JWT", "alg": "RS256"})
        payload += '=' * (-len(payload) % 4)  # add padding
        self.assertEqual(
            json.loads(base64.b64decode(payload).decode("utf-8")),
            payload_in)

    def test_encode_jwt__issuer_special_chars(self):
        # validate URI style issuers are supported
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        settings_copy['JWT_ISSUERS'] = {
            issuer_special_chars: {'private_key': privkey}
        }

        payload_in = self._get_payload()
        payload_in['iss'] = issuer_special_chars

        with override_settings(OAUTH2_PROVIDER=settings_copy):
            encoded = utils.encode_jwt(payload_in)

        self.assertIn(type(encoded).__name__, ('unicode', 'str'))
        headers, payload, verify_signature = encoded.split(".")
        self.assertDictEqual(
            json.loads(base64.b64decode(headers)),
            {"typ": "JWT", "alg": "RS256"})
        payload += '=' * (-len(payload) % 4)  # add padding
        self.assertEqual(
            json.loads(base64.b64decode(payload).decode("utf-8")),
            payload_in)

    def test_encode_jwt_explicit_issuer(self):
        payload_in = self._get_payload()
        payload_in['iss'] = 'different-issuer'
        encoded = utils.encode_jwt(payload_in, 'issuer')
        self.assertIn(type(encoded).__name__, ('unicode', 'str'))
        headers, payload, verify_signature = encoded.split(".")
        self.assertDictEqual(
            json.loads(base64.b64decode(headers)),
            {"typ": "JWT", "alg": "RS256"})
        payload += '=' * (-len(payload) % 4)  # add padding
        self.assertEqual(
            json.loads(base64.b64decode(payload).decode("utf-8")),
            payload_in)

    def test_encode_jwt_hs256(self):
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        settings_copy['JWT_ISSUERS'] = {
            'issuer': {
                'private_key': 'test',
                'encoding_algorithm': 'HS256',
            }
        }

        payload_in = self._get_payload()

        with override_settings(OAUTH2_PROVIDER=settings_copy):
            encoded = utils.encode_jwt(payload_in)

        self.assertIn(type(encoded).__name__, ('unicode', 'str'))
        headers, payload, verify_signature = encoded.split('.')
        self.assertDictEqual(
            json.loads(base64.b64decode(headers)),
            {'typ': 'JWT', 'alg': 'HS256'})
        payload += '=' * (-len(payload) % 4)
        self.assertEqual(
            json.loads(base64.b64decode(payload).decode('utf-8')),
            payload_in)


class DecodeJWTTest(PythonTestCase):
    def _get_payload(self):
        now = datetime.utcnow()
        return {
            'iss': 'issuer',
            'exp': now + timedelta(seconds=10),
            'iat': now,
            'sub': 'subject',
            'usr': 'some_usr',
            'org': 'some_org',
        }

    def test_invalid_token(self):
        # Validate an error is thrown if the token is invalid
        self.assertRaises(jwt.InvalidTokenError, utils.decode_jwt, 'abc')

    def test_no_public_keys_defined(self):
        # Validate that an error is thrown with neither public_key_func or
        # public_key are defined.
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        if 'public_key' in settings_copy['JWT_ISSUERS']['issuer']:
            del settings_copy['JWT_ISSUERS']['issuer']['public_key']
        if 'public_key_func' in settings_copy['JWT_ISSUERS']['issuer']:
            del settings_copy['JWT_ISSUERS']['issuer']['public_key_func']

        payload = self._get_payload()
        with override_settings(OAUTH2_PROVIDER=settings_copy):
            token = utils.encode_jwt(payload)
            self.assertRaises(
                ImproperlyConfigured, utils.decode_jwt, token)

    @patch('oauth2_provider_jwt.utils.jwt.decode')
    def test_favor_public_key_func(self, jwtdecode_mock):
        # Validate that public_key_func is preferred when both public_key_func
        # and public_key are defined.
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        settings_copy['JWT_ISSUERS']['issuer']['public_key'] = 'dontuse'
        settings_copy['JWT_ISSUERS']['issuer']['public_key_func'] = \
            'tests.test_utils.public_key_func'
        keyfn_retval = public_key_func('issuer', '123')

        with patch('tests.test_utils.public_key_func') as keyfn_mock:
            keyfn_mock.return_value = keyfn_retval
            with override_settings(OAUTH2_PROVIDER=settings_copy):
                # This will raise a ValueError about not being able to
                # deserialize data if the string is used instead of the
                # function.
                token = utils.encode_jwt(self._get_payload())
                utils.decode_jwt(token)
            keyfn_mock.assert_called()
        jwtdecode_mock.assert_called_with(
            token, keyfn_retval, algorithms=['RS256', ])

    def test_none_public_key(self):
        # Validate that a public_key of None causes an error.
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        settings_copy['JWT_ISSUERS']['issuer']['public_key'] = None
        settings_copy['JWT_ISSUERS']['issuer']['public_key_func'] = None

        with override_settings(OAUTH2_PROVIDER=settings_copy):
            token = utils.encode_jwt(self._get_payload())
            self.assertRaises(
                ImproperlyConfigured, utils.decode_jwt, token)

    def test_blank_public_key(self):
        # Validate that a blank public_key causes an error.
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        settings_copy['JWT_ISSUERS']['issuer']['public_key'] = ''
        settings_copy['JWT_ISSUERS']['issuer']['public_key_func'] = ''

        with override_settings(OAUTH2_PROVIDER=settings_copy):
            token = utils.encode_jwt(self._get_payload())
            self.assertRaises(
                ImproperlyConfigured, utils.decode_jwt, token)

    def test_public_key_func(self):
        # Validate that public_key_func is called.
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        del settings_copy['JWT_ISSUERS']['issuer']['public_key']
        settings_copy['JWT_ISSUERS']['issuer']['public_key_func'] = \
            'tests.test_utils.public_key_func'

        payload = self._get_payload()
        with override_settings(OAUTH2_PROVIDER=settings_copy):
            token = utils.encode_jwt(payload)
            decoded_payload = utils.decode_jwt(token)

        self.assertEqual(decoded_payload, payload)

    def test_decode_jwt_expired(self):
        payload = self._get_payload()
        now = datetime.utcnow()
        payload['exp'] = now - timedelta(seconds=1)
        payload['iat'] = now
        jwt_value = utils.encode_jwt(payload)
        self.assertRaises(jwt.ExpiredSignatureError, utils.decode_jwt,
                          jwt_value)

    def test_decode_jwt_rs256(self):
        payload = self._get_payload()
        jwt_value = utils.encode_jwt(payload)
        payload_out = utils.decode_jwt(jwt_value)
        self.assertDictEqual(payload, payload_out)

    def test_decode_jwt__issuer_special_chars(self):
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        settings_copy['JWT_ISSUERS'] = {
            issuer_special_chars: {
                'private_key': privkey,
                'public_key': pubkey,
            }
        }

        with override_settings(OAUTH2_PROVIDER=settings_copy):
            payload = self._get_payload()
            payload['iss'] = issuer_special_chars
            jwt_value = utils.encode_jwt(payload)
            payload_out = utils.decode_jwt(jwt_value)

        self.assertDictEqual(payload, payload_out)

    def test_decode_jwt_explicit_issuer(self):
        payload = self._get_payload()
        payload['iss'] = 'different-issuer'
        jwt_value = utils.encode_jwt(payload, 'issuer')
        payload_out = utils.decode_jwt(jwt_value, 'issuer')
        self.assertDictEqual(payload, payload_out)

    def test_decode_jwt_hs256(self):
        settings_copy = deepcopy(settings.OAUTH2_PROVIDER)
        settings_copy['JWT_ISSUERS'] = {
            'issuer': {
                'private_key': 'test',
                'public_key': 'test',
                'encoding_algorithm': 'HS256',
            }
        }
        with override_settings(OAUTH2_PROVIDER=settings_copy):
            payload = self._get_payload()
            jwt_value = utils.encode_jwt(payload)
            payload_out = utils.decode_jwt(jwt_value)
        self.assertDictEqual(payload, payload_out)
