import ast
import json
import logging

from urllib.parse import urlencode, urlparse, parse_qs  # noqa

from django.conf import settings
from django.utils.module_loading import import_string
from oauth2_provider import views
from oauth2_provider.http import OAuth2ResponseRedirect
from oauth2_provider.models import get_access_token_model

from .utils import generate_payload, encode_jwt

logger = logging.getLogger(__name__)


class MissingIdAttribute(Exception):
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
                is_machine_to_machine_workflow = self._is_machine_to_machine_workflow(request)
                jwt, _ = TokenView()._get_access_token_jwt(request, content, is_machine_to_machine_workflow)
                response = OAuth2ResponseRedirect(
                    '{}&access_token_jwt={}'.format(response.url, jwt),
                    response.allowed_schemes)
        return response


class TokenView(views.TokenView):
    def _get_access_token_jwt(self, request, content, is_machine_to_machine_workflow=False):
        extra_data = {}
        issuer = settings.JWT_ISSUER
        payload_enricher = getattr(settings, 'JWT_PAYLOAD_ENRICHER', None)
        if payload_enricher:
            fn = import_string(payload_enricher)
            extra_data = fn(request)

        if 'scope' in content:
            extra_data['scope'] = content['scope']

        token_model = get_access_token_model().objects.get(
            token=content['access_token']
        )

        id_attribute = getattr(settings, 'JWT_ID_ATTRIBUTE', None)
        if id_attribute:
            id_value = getattr(token_model.user, id_attribute, None)
            if not id_value:
                if is_machine_to_machine_workflow:  # Check if registered app has any user attached
                    id_value = getattr(token_model.application.user, id_attribute, None)
                    if not id_value:
                        raise MissingIdAttribute()
                else:
                    raise MissingIdAttribute()
            extra_data[id_attribute] = str(id_value)

        payload = generate_payload(issuer, content['expires_in'], **extra_data)
        token = encode_jwt(payload)
        token_model.token = token
        token_model.save()
        return token, token_model

    @staticmethod
    def _is_jwt_config_set(is_machine_to_machine_workflow=False):
        issuer = getattr(settings, 'JWT_ISSUER', '')
        private_key_name = 'JWT_PRIVATE_KEY_{}'.format(issuer.upper())
        private_key = getattr(settings, private_key_name, None)
        # JWT_ID_ATTRIBUTE not needed for client_credentials Grant Type
        id_attribute_default = "FAKE" if is_machine_to_machine_workflow else ""
        id_attribute = getattr(settings, 'JWT_ID_ATTRIBUTE', id_attribute_default)
        if issuer and private_key and id_attribute:
            return True
        else:
            return False

    def _is_machine_to_machine_workflow(self, request):
        return 'client_credentials' == request.POST.get('grant_type', '') \
            or 'client_credentials' == request.GET.get('grant_type', '')

    def post(self, request, *args, **kwargs):
        response = super(TokenView, self).post(request, *args, **kwargs)
        content = ast.literal_eval(response.content.decode("utf-8"))
        if response.status_code == 200 and 'access_token' in content:
            is_machine_to_machine_workflow = self._is_machine_to_machine_workflow(request)
            if not TokenView._is_jwt_config_set(is_machine_to_machine_workflow):
                logger.warning(
                    'Missing JWT configuration, skipping token build')
            else:
                try:
                    access_token_jwt, token_model = self._get_access_token_jwt(
                        request, content, is_machine_to_machine_workflow)
                    content['access_token'] = access_token_jwt
                    try:
                        content = bytes(json.dumps(content), 'utf-8')
                    except TypeError:
                        content = bytes(json.dumps(content).encode("utf-8"))

                    # Swap token which was previously generated for a JWT token
                    token_model.token = access_token_jwt
                    token_model.save()
                    response.content = content
                except MissingIdAttribute:
                    response.status_code = 400
                    response.content = json.dumps({
                        "error": "invalid_request",
                        "error_description": "App not configured correctly. "
                                             "Please set JWT_ID_ATTRIBUTE.",
                    })
        return response
