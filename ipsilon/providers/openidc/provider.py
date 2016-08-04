# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.providers.openidc.api import APIError, APIRequest
from ipsilon.util.security import generate_random_secure_string


import cherrypy
import json
import time
import requests
from urlparse import urlparse


def get_url_hostpart(url):
    try:
        o = urlparse(url)
        return o.hostname
    except:  # pylint: disable=bare-except
        return url


def validate_client_metadata(client_metadata):
    # Fill in defaults for optional arguments
    client_metadata['response_types'] = client_metadata.get(
        'response_types', ['code'])
    client_metadata['grant_types'] = client_metadata.get(
        'grant_types', ['authorization_code'])
    client_metadata['application_type'] = client_metadata.get(
        'application_type', 'web')
    client_metadata['contacts'] = client_metadata.get('contacts', [])
    client_metadata['subject_type'] = client_metadata.get('subject_type',
                                                          'pairwise')
    client_metadata['id_token_signed_response_alg'] = client_metadata.get(
        'id_token_signed_response_alg', 'RS256')
    client_metadata['token_endpoint_auth_method'] = client_metadata.get(
        'token_endpoint_auth_method', 'client_secret_basic')
    client_metadata['require_auth_time'] = client_metadata.get(
        'require_auth_time', False)

    # Check the client metadata received
    if 'redirect_uris' not in client_metadata:
        raise APIError(400, 'invalid_client_metadata',
                       'missing redirect_uris')

    if client_metadata['application_type'] not in ['web', 'native']:
        raise APIError(400, 'invalid_client_metadata',
                       'application_type invalid')

    for redirect_uri in client_metadata['redirect_uris']:
        if '#' in redirect_uri:
            raise APIError(400, 'invalid_redirect_uri',
                           'redirect_uri contains fragment')

        if client_metadata['application_type'] == 'web':
            # In this case, it must be https:// and not https://localhost
            if (not redirect_uri.startswith('https://') or
                    redirect_uri.startswith('https://localhost')):
                raise APIError(400, 'invalid_redirect_uri',
                               'redirect_uri %s not valid' % redirect_uri)

        elif client_metadata['application_type'] == 'native':
            # In this case, it must be http://localhost, or something
            # that is not http:// or https://
            if (redirect_uri.startswith('https://') or
                    (redirect_uri.startswith('http://') and
                     not redirect_uri.startswith('http://localhost'))):
                raise APIError(400, 'invalid_redirect_uri',
                               'redirect_uri %s not valid' % redirect_uri)

    if 'initiate_login_uri' in client_metadata:
        if not client_metadata['initiate_login_uri'].startswith(
                'https://'):
            raise APIError(400, 'invalid_client_metadata',
                           'initiate_login_uri must be https')

    if 'sector_identifier_uri' not in client_metadata:
        hostname = None
        for redir_uri in client_metadata['redirect_uris']:
            cur_host = get_url_hostpart(redir_uri)
            if not cur_host:
                raise APIError(400, 'invalid_client_metadata',
                               'Unable to parse hostname from ' +
                               'redirect_uri %s' % redir_uri)
            if hostname is not None and cur_host != hostname:
                raise APIError(400, 'invalid_client_metadata',
                               'Multiple redirect_uri hostnames without ' +
                               'sector_identifier_uri')
            hostname = cur_host
    else:
        if not client_metadata['sector_identifier_uri'].startswith(
                'https://'):
            raise APIError(400, 'invalid_client_metadata',
                           'sector_identifier_uri must be https')

        try:
            resp = requests.get(client_metadata['sector_identifier_uri'])
            resp = resp.json()
            for redirect_uri in client_metadata['redirect_uris']:
                if redirect_uri not in resp:
                    raise APIError(400, 'invalid_client_metadata',
                                   'redirect_uri %s not in ' +
                                   'sector_identifier_uri document' %
                                   redirect_uri)
        except Exception as ex:
            raise APIError(400, 'invalid_client_metadata',
                           'unable to process sector_identifier_uri: %s' % ex)

    if 'code' in client_metadata['response_types']:
        if 'authorization_code' not in client_metadata['grant_types']:
            raise APIError(400, 'invalid_client_metadata',
                           'authorization_code missing with code')

    if ('token' in client_metadata['response_types'] or
            'id_token' in client_metadata['response_types']):
        if 'implicit' not in client_metadata['grant_types']:
            raise APIError(400, 'invalid_client_metadata',
                           'implicit missing with token or id_token')

    if 'jwks' in client_metadata and 'jwks_uri' in client_metadata:
        raise APIError(400, 'invalid_client_metadata',
                       'both jwks and jwks_uri provided')


class Registration(APIRequest):

    def POST(self, *args, **kwargs):
        if not self.cfg.allow_dynamic_client_registration:
            raise APIError(400, 'invalid_request',
                           'dynamic client registration has been disabled')

        try:
            client_metadata = json.loads(cherrypy.request.rfile.read())
        except:
            raise APIError(400, 'invalid_client_metadata',
                           'unable to parse metadata')
        self.debug('Received client registration request: %s'
                   % client_metadata)

        validate_client_metadata(client_metadata)

        client_metadata['client_secret'] = \
            generate_random_secure_string()
        client_metadata['client_secret_expires_at'] = 0  # FIXME: Expire?
        client_metadata['client_id_issued_at'] = int(time.time())

        # Store some internal data
        client_metadata['ipsilon_internal'] = {
            'trusted': False
        }

        # Store and add reg uri
        client_id = self.cfg.datastore.registerDynamicClient(client_metadata)
        client_metadata['client_id'] = client_id

        # Clear internal data from returned values
        del client_metadata['ipsilon_internal']

        # FIXME: Offer this once we add a ClientConfiguration endpoint
        # client_metadata['registration_access_token'] = \
        #    generate_random_secure_string()
        # client_metadata['registration_client_uri'] = '%s%s' % (
        #    self.cfg.endpoint_url, 'ClientConfiguration')

        return self._respond(client_metadata)
