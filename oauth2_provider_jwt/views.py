import ast
import json
import logging

from urllib.parse import urlencode, urlparse, parse_qs  # noqa

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
from oauth2_provider import views
from oauth2_provider.http import OAuth2ResponseRedirect
from oauth2_provider.models import get_access_token_model

from .utils import generate_payload, encode_jwt, get_issuer_settings

logger = logging.getLogger(__name__)


class MissingIdAttributeValue(Exception):
    # Indicates the value for the id_attribute_map from the User model was
    # missing, or None
    pass


class JWTAuthorizationView(views.AuthorizationView):
    def get(self, request, *args, **kwargs):
        response = super(JWTAuthorizationView, self).get(request, *args,
                                                         **kwargs)
        if request.GET.get('response_type', None) == 'token' \
                and response.status_code == 302:
            url = urlparse(response.url)
            params = parse_qs(url.fragment)
            if params:
                content = {
                    'access_token': params['access_token'][0],
                    'expires_in': int(params['expires_in'][0]),
                    'scope': params['scope'][0]
                }
                jwt = TokenView()._get_access_token_jwt(request, content)
                response = OAuth2ResponseRedirect(
                    '{}&access_token_jwt={}'.format(response.url, jwt),
                    response.allowed_schemes)
        return response


class TokenView(views.TokenView):
    @staticmethod
    def _get_access_token_jwt(request, content):
        extra_data = {}
        issuer = settings.OAUTH2_PROVIDER['JWT_DEFAULT_ISSUER']
        iss_settings = get_issuer_settings(issuer)

        token = get_access_token_model().objects.get(
            token=content['access_token']
        )

        if 'scope' in content:
            extra_data['scope'] = content['scope']

        id_attribute_map = iss_settings.get('id_attribute_map', None)
        if id_attribute_map:
            if 'attribute' not in id_attribute_map \
               or 'claim' not in id_attribute_map:
                raise ImproperlyConfigured(
                    f'id_attribute_map missing data for issuer {issuer}')
            id_value = getattr(
                token.user,
                id_attribute_map['attribute'],
                None)
            if not id_value:
                raise MissingIdAttributeValue()
            extra_data[id_attribute_map['claim']] = str(id_value)

        payload = generate_payload(issuer, content['expires_in'], **extra_data)

        payload_enricher = iss_settings.get('payload_enricher_func', None)
        if payload_enricher:
            fn = import_string(payload_enricher)
            enriched_data = fn(
                request=request,
                token_content=content,
                token_obj=token,
                current_claims=payload)

            if iss_settings.get('overwrite_token_with_enricher', False):
                logger.debug(
                    'Overwriting default JWT with value returned from '
                    'enrichment function')
                payload = enriched_data
            else:
                payload.update(enriched_data)

        token = encode_jwt(payload, issuer)
        return token

    @staticmethod
    def _is_jwt_config_set():
        """Determines if settings are defined to act as a JWT provider."""
        issuer = settings.OAUTH2_PROVIDER.get('JWT_DEFAULT_ISSUER', None)
        try:
            iss_settings = get_issuer_settings(issuer)
        except ImproperlyConfigured:
            return False

        private_key = iss_settings.get('private_key', None)

        if issuer and private_key:
            return True
        else:
            return False

    def post(self, request, *args, **kwargs):
        response = super(TokenView, self).post(request, *args, **kwargs)
        content = ast.literal_eval(response.content.decode("utf-8"))
        if response.status_code == 200 and 'access_token' in content:
            if not TokenView._is_jwt_config_set():
                logger.warning(
                    'Not configured to be a JWT provider. Skipping JWT '
                    'creation')
            else:
                try:
                    content['access_token_jwt'] = self._get_access_token_jwt(
                        request, content)
                    try:
                        content = bytes(json.dumps(content), 'utf-8')
                    except TypeError:
                        content = bytes(json.dumps(content).encode("utf-8"))
                    response.content = content
                except MissingIdAttributeValue:
                    issuer = settings.OAUTH2_PROVIDER.get(
                        'JWT_DEFAULT_ISSUER', '<unknown>')
                    logger.warning(
                        f'Value for id JWT claim defined on issuer {issuer} '
                        'is empty or null. Please verify id_attribute_map '
                        'defines a unique and not null field on the User '
                        'model.')
                    response.status_code = 500
                    response.content = json.dumps({
                        'error': 'configuration_error',
                        'error_description': 'See logs for more detail.',
                    })
        return response
