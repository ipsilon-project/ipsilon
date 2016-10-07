# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.providers.common import ProviderPageBase
from ipsilon.providers.common import InvalidRequest
from ipsilon.util.policy import Policy
from ipsilon.util.trans import Transaction
from ipsilon.providers.openidc.api import (Token,
                                           TokenInfo,
                                           UserInfo)
from ipsilon.providers.openidc.provider import (get_url_hostpart,
                                                Registration)
from ipsilon.util.user import UserSession

from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK, JWKSet
from jwcrypto.jws import default_allowed_algs as jws_default_allowed_algs

import base64
import cherrypy
import hashlib
import requests
import time
import json
import urllib

URLROOT = 'openidc'


class AuthenticateRequest(ProviderPageBase):

    def __init__(self, site, provider, *args, **kwargs):
        super(AuthenticateRequest, self).__init__(site, provider,
                                                  *args, **kwargs)
        self.trans = None

    def _preop(self, *args, **kwargs):
        try:
            # generate a new id or get current one
            self.trans = Transaction('openidc', **kwargs)
            if (self.trans.cookie and
                    self.trans.cookie.value != self.trans.provider):
                self.debug('Invalid transaction, %s != %s' % (
                           self.trans.cookie.value, self.trans.provider))
        except Exception, e:  # pylint: disable=broad-except
            self.debug('Transaction initialization failed: %s' % repr(e))
            raise cherrypy.HTTPError(400, 'Invalid transaction id')

    def pre_GET(self, *args, **kwargs):
        self._preop(*args, **kwargs)

    def pre_POST(self, *args, **kwargs):
        self._preop(*args, **kwargs)

    # get attributes, and apply policy mapping and filtering
    def _source_attributes(self, session):
        policy = Policy(self.cfg.default_attribute_mapping,
                        self.cfg.default_allowed_attributes)
        userattrs = session.get_user_attrs()
        mappedattrs, _ = policy.map_attributes(userattrs)
        attributes = policy.filter_attributes(mappedattrs)
        self.debug('Filterd attributes: %s' % repr(attributes))
        return attributes

    def _respond(self, request, contents):
        url = request['redirect_uri']
        response_mode = request.get('response_mode', None)
        response_type = request.get('response_type', [])
        if 'none' in response_type:
            response_mode = 'none'
            self.debug('none response_type, using none response_mode')
        elif 'id_token' in response_type or 'token' in response_type:
            if response_mode in [None, 'query']:
                # If no response_mode or query response_mode is selected,
                # fall back to the default for id_token or token requests,
                # which is fragment encoding. The query override is because
                # the specifications specify that with id_token or token,
                # query MUST NOT be used.
                response_mode = 'fragment'
                self.debug('id_token requesed, fragment response_mode forced')
        elif not response_mode:
            # We still have no response_mode, fall back to query
            # This also happens in case we were unable to parse the request,
            # and as such were unable to get the response_mode the client
            # preferred
            response_mode = 'query'
            self.debug('Using default query response mode')

        # If the client sent a state, we need to pass that back
        if 'state' in request:
            contents['state'] = request['state']

        # Build a response-string, which is sent with either query, form
        # or fragment responses
        if response_mode in ['query', 'fragment']:

            separator = '?'
            if response_mode == 'fragment':
                separator = '#'
            if separator not in url:
                url += separator
            else:
                url += '&'

            url += urllib.urlencode(contents)

        if response_mode in ['query', 'fragment', 'none']:
            raise cherrypy.HTTPRedirect(url)
        elif response_mode == 'form_post':
            context = {
                "title": "Continue",
                "redirect_url": url,
                "response_info": contents
            }
            return self._template(URLROOT + '/form_response.html', **context)
        else:
            raise InvalidRequest('Invalid response_mode requested')

    def _respond_error(self, request, error, message):
        self.log('Responding with error: %s, message: %s' % (error, message))
        if request.get('redirect_uri') is None:
            self.log('No valid redirect URI')
            raise InvalidRequest('Request is missing redirct_uri')

        return self._respond(request, {'error': error,
                                       'error_description': message})

    def _authz_stack_check(self, request_data, client, username, userattrs):
        provinfo = client.copy()
        provinfo['url'] = provinfo.pop('client_uri')
        if provinfo['ipsilon_internal']['trusted']:
            # Trusted OpenIDC clients are added by an Ipsilon admin, so we can
            # safely use the client name
            provinfo['name'] = provinfo.pop('client_name')

        if not self._site['authz'].authorize_user('openidc', provinfo,
                                                  username, userattrs):
            self.error('Authorization denied by authorization provider')
            return self._respond_error(request_data, 'access_denied',
                                       'authorization denied')
        else:
            return None


class Authorization(AuthenticateRequest):

    def start_authz(self, arguments):
        request_data = {
            'scope': [],
            'response_type': [],
            'client_id': None,
            'redirect_uri': None,
            'state': None,
            'response_mode': None,
            'nonce': None,
            'display': None,
            'prompt': [],
            'max_age': None,
            'ui_locales': None,
            'id_token_hint': None,
            'login_hint': None,
            'acr_values': None,
            'claims': '{}'
        }

        # Get the request
        # Step 1: get the get query arguments
        for data in request_data.keys():
            if arguments.get(data, None):
                request_data[data] = arguments[data]

        # This is a workaround for python not understanding the splits we
        # do later
        if request_data['prompt'] == []:
            request_data['prompt'] = None

        for required_arg in ['scope',
                             'response_type',
                             'client_id']:
            if request_data[required_arg] is None or \
                    len(request_data[required_arg]) == 0:
                return self._respond_error(request_data,
                                           'invalid_request',
                                           'missing required argument %s' %
                                           required_arg)

        client = self.cfg.datastore.getClient(request_data['client_id'])
        if not client:
            return self._respond_error(request_data,
                                       'unauthorized_client',
                                       'Unknown client ID')

        request_data['response_type'] = request_data.get('response_type',
                                                         '').split(' ')
        for rtype in request_data['response_type']:
            if rtype not in ['id_token', 'token', 'code']:
                return self._respond_error(request_data,
                                           'unsupported_response_type',
                                           'response type %s is not supported'
                                           % rtype)

        if request_data['response_type'] != ['code'] and \
                not request_data['nonce']:
            return self._respond_error(request_data,
                                       'invalid_request',
                                       'nonce missing in non-code flow')

        # Step 2: get any provided request or request_uri
        if 'request' in arguments or 'request_uri' in arguments:
            # This is a JWT-encoded request
            if 'request' in arguments and 'request_uri' in arguments:
                return self._respond_error(request_data,
                                           'invalid_request',
                                           'both request and request_uri ' +
                                           'provided')

            if 'request' in arguments:
                jwt_object = arguments['request']
            else:
                try:
                    # FIXME: MAY cache this at client registration time and
                    # cache permanently until client registration is changed.
                    jwt_object = requests.get(arguments['request_uri']).text
                except Exception as ex:  # pylint: disable=broad-except
                    self.debug('Unable to get request: %s' % ex)
                    return self._respond_error(request_data,
                                               'invalid_request',
                                               'unable to parse request_uri')

            jwt_request = None
            try:
                # FIXME: Implement decryption
                decoded = JWT(jwt=jwt_object)
                if client['request_object_signing_alg'] != 'none':
                    # Client told us we need to check signature
                    if decoded.token.jose_header['alg'] != \
                            client['request_object_signing_alg']:
                        raise Exception('Invalid algorithm used: %s'
                                        % decoded.token.jose_header['alg'])

                    if client['request_object_signing_alg'] == 'none':
                        jwt_request = json.loads(
                            decoded.token.objects['payload'])
                    else:
                        keyset = None
                        if client['jwks']:
                            keys = json.loads(client['jkws'])
                        else:
                            keys = requests.get(client['jwks_uri']).json()
                        keyset = JWKSet()
                        for key in keys['keys']:
                            keyset.add(JWK(**key))
                        key = keyset.get_key(decoded.token.jose_header['kid'])
                        decoded = JWT(jwt=jwt_object, key=key)
                        jwt_request = json.loads(decoded.claims)

            except Exception as ex:  # pylint: disable=broad-except
                self.debug('Unable to parse request: %s' % ex)
                return self._respond_error(request_data,
                                           'invalid_request',
                                           'unable to parse request')

            if 'response_type' in jwt_request:
                jwt_request['response_type'] = \
                    jwt_request['response_type'].split(' ')
                if jwt_request['response_type'] != \
                        request_data['response_type']:
                    return self._respond_error(request_data,
                                               'invalid_request',
                                               'response_type does not match')

            if 'client_id' in jwt_request:
                if jwt_request['client_id'] != request_data['client_id']:
                    return self._respond_error(request_data,
                                               'invalid_request',
                                               'client_id does not match')

            for data in request_data.keys():
                if data in jwt_request:
                    request_data[data] = jwt_request[data]

        # Split these options since they are space-separated lists
        for to_split in ['prompt',
                         'ui_locales',
                         'acr_values',
                         'scope']:
            if request_data[to_split] is not None:
                # We know better than pylint in this regard
                # pylint: disable=no-member
                request_data[to_split] = request_data[to_split].split(' ')
            else:
                request_data[to_split] = []

        # Start checking the request
        if request_data['redirect_uri'] is None:
            if len(client['redirect_uris']) != 1:
                return self._respond_error(request_data,
                                           'invalid_request',
                                           'missing redirect_uri')
            else:
                request_data['redirect_uri'] = client['redirect_uris'][0]

        for scope in request_data['scope']:
            if scope not in self.cfg.supported_scopes:
                return self._respond_error(request_data,
                                           'invalid_scope',
                                           'unknown scope %s requested' %
                                           scope)

        for response_type in request_data['response_type']:
            if response_type not in ['code', 'id_token', 'token']:
                return self._respond_error(request_data,
                                           'unsupported_response_type',
                                           'response_type %s is unknown'
                                           % response_type)

        if request_data['redirect_uri'] not in client['redirect_uris']:
            raise InvalidRequest('Invalid redirect_uri')

        # Build the "claims" values from scopes
        try:
            request_data['claims'] = json.loads(request_data['claims'])
        except Exception, ex:  # pylint: disable=broad-except
            return self._respond_error(request_data,
                                       'invalid_request',
                                       'claims malformed: %s' % ex)
        if 'userinfo' not in request_data['claims']:
            request_data['claims']['userinfo'] = {}
        if 'id_token' not in request_data['claims']:
            request_data['claims']['id_token'] = {}

        scopes_to_claim = {
            'profile': [
                'name', 'family_name', 'given_name', 'middle_name', 'nickname',
                'preferred_username', 'profile', 'picture', 'website',
                'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'
            ],
            'email': ['email', 'email_verified'],
            'address': ['address'],
            'phone': ['phone_number', 'phone_number_verified']
        }
        for scope in scopes_to_claim:
            if scope in request_data['scope']:
                for claim in scopes_to_claim[scope]:
                    if claim not in request_data['claims']:
                        # pylint: disable=invalid-sequence-index
                        request_data['claims']['userinfo'][claim] = None

        # Add claims from extensions
        for n, e in self.cfg.extensions.available().items():
            data = e.get_claims(request_data['scope'])
            self.debug('%s returned %s' % (n, repr(data)))
            for claim in data:
                # pylint: disable=invalid-sequence-index
                request_data['claims']['userinfo'][claim] = None

        # Store data so we can continue with the request
        us = UserSession()
        user = us.get_user()

        returl = '%s/%s/Continue?%s' % (
            self.basepath, URLROOT, self.trans.get_GET_arg())
        data = {'login_target': client.get('client_name', None),
                'login_return': returl,
                'openidc_stage': 'continue',
                'openidc_request': json.dumps(request_data)}

        if request_data['login_hint']:
            data['login_username'] = request_data['login_hint']

        if not data['login_target']:
            data['login_target'] = get_url_hostpart(
                request_data['redirect_uri'])

        # Decide what to do with the request
        if request_data['max_age'] is None:
            request_data['max_age'] = client.get('default_max_age', None)

        needs_auth = True
        if not user.is_anonymous:
            if request_data['max_age'] in [None, 0]:
                needs_auth = False
            else:
                auth_time = us.get_user_attrs()['_auth_time']
                needs_auth = ((int(auth_time) +
                              int(request_data['max_age'])) <=
                              int(time.time()))

        if needs_auth or 'login' in request_data['prompt']:
            if 'none' in request_data['prompt']:
                # We were asked not to provide a UI. Answer with false.
                return self._respond_error(request_data,
                                           'login_required',
                                           'user interface required')

            # Either the user wasn't logged in, or we were explicitly
            # asked to re-auth them. Let's do so!
            us.logout(user)

            # Let the user go to auth
            self.trans.store(data)
            redirect = '%s/login?%s' % (self.basepath,
                                        self.trans.get_GET_arg())
            self.debug('Redirecting: %s' % redirect)
            raise cherrypy.HTTPRedirect(redirect)

        # Return error if authz check fails
        authz_check_res = self._authz_stack_check(request_data, client,
                                                  user.name,
                                                  us.get_user_attrs())
        if authz_check_res:
            return authz_check_res

        self.trans.store(data)
        # The user was already signed on, and no request to re-assert its
        # identity. Let's forward directly to /Continue/
        self.debug('Redirecting: %s' % returl)
        raise cherrypy.HTTPRedirect(returl)

    def GET(self, *args, **kwargs):
        return self.start_authz(kwargs)

    def POST(self, *args, **kwargs):
        return self.start_authz(kwargs)


class Continue(AuthenticateRequest):

    def _respond_success(self, request, client, user, userinfo):
        # Answer the current request with a successful response.
        response = {}

        if client['subject_type'] == 'public':
            userinfo['sub'] = user.name
        else:
            h = hashlib.sha256()
            if client['sector_identifier_uri']:
                domain = get_url_hostpart(
                    client['sector_identifier_uri'])
            else:
                # We are guaranteed that we either have a sector_identifier_uri
                # or that the hostpart of all redirect_uris are equal
                domain = get_url_hostpart(client['redirect_uris'][0])
            h.update(domain)
            h.update(user.name)
            h.update(self.cfg.idp_subject_salt)
            userinfo['sub'] = h.hexdigest()

        claims_userinfo = {}
        for requested_claim in request['claims']['userinfo']:
            if requested_claim in userinfo:
                claims_userinfo[requested_claim] = userinfo[requested_claim]
        claims_userinfo['sub'] = userinfo['sub']

        userinfocode = None
        if 'openid' in request['scope']:
            userinfocode = self.cfg.datastore.storeUserInfo(claims_userinfo)

        if 'token' in request['response_type']:
            # Asked to return token in authz response
            # Flows: Hybrid and Implicit
            token = self.cfg.datastore.issueToken(
                request['client_id'],
                user.name,
                request['scope'],
                False,
                userinfocode)
            del token['token_id']
            response['access_token'] = token['access_token']
            response['token_type'] = 'Bearer'
            response['expires_in'] = token['expires_in']

        if 'code' in request['response_type']:
            # Asked to return authorization code
            # Flows: Authorization code and Hybrid
            response['code'] = self.cfg.datastore.issueAuthorizationCode(
                request['client_id'],
                user.name,
                request['scope'],
                userinfo,
                request['redirect_uri'],
                userinfocode)

        if 'openid' in request['scope']:
            id_token = {}

            # Build the id_token
            for requested_claim in request['claims']['id_token']:
                if requested_claim in userinfo:
                    id_token[requested_claim] = userinfo[requested_claim]

            id_token['sub'] = userinfo['sub']
            id_token['iss'] = self.cfg.endpoint_url
            id_token['aud'] = request['client_id']
            id_token['exp'] = int(time.time()) + 600
            id_token['iat'] = int(time.time())
            id_token['auth_time'] = userinfo['_auth_time']
            if 'nonce' in request:
                id_token['nonce'] = request['nonce']
            id_token['acr'] = '0'
            id_token['amr'] = json.dumps([])
            id_token['azp'] = request['client_id']

            if 'code' in response:
                # Add c_hash
                id_token['c_hash'] = self._calc_hash(response['code'])

            if 'access_token' in response:
                # Add at_hash
                id_token['at_hash'] = self._calc_hash(response['access_token'])

            sig = JWT(header={'alg': 'RS256',
                              'kid': self.cfg.idp_sig_key_id},
                      claims=id_token)
            # FIXME: Maybe add other algorithms in the future
            sig.make_signed_token(self.cfg.keyset.get_key(
                self.cfg.idp_sig_key_id))
            # FIXME: Maybe encrypt in the future
            signed_id_token = sig.serialize(compact=True)

            if 'code' in response:
                self.cfg.datastore.storeAuthorizationIDToken(response['code'],
                                                             signed_id_token)

            if 'id_token' in request['response_type']:
                response['id_token'] = signed_id_token

        return self._respond(request, response)

    def _calc_hash(self, msg):
        h = hashlib.sha256(msg.encode()).digest()
        return base64.urlsafe_b64encode(h[:16]).rstrip(b'=').decode()

    def _perform_continue(self, *args, **kwargs):
        us = UserSession()
        user = us.get_user()

        if user.is_anonymous:
            raise InvalidRequest('User not authenticated at continue')

        transdata = self.trans.retrieve()
        stage = transdata.get('openidc_stage', None)
        request_data = transdata.get('openidc_request', None)
        if stage not in ['continue', 'consent'] or request_data is None:
            raise InvalidRequest('Invalid stage or no request')

        # Since we have openidc_stage continue or consent, request is sane
        try:
            request_data = json.loads(request_data)
        except:
            raise InvalidRequest('Unable to re-parse stored request')

        client = self.cfg.datastore.getClient(request_data['client_id'])
        if not client:
            return self._respond_error(request_data,
                                       'unauthorized_client',
                                       'Unknown client ID')

        # Return error if authz check fails
        authz_check_res = self._authz_stack_check(request_data, client,
                                                  user.name,
                                                  us.get_user_attrs())
        if authz_check_res:
            return authz_check_res

        userattrs = self._source_attributes(us)
        if client['ipsilon_internal']['trusted']:
            # No consent needed, approve
            self.debug('Client trusted, no consent needed')
            return self._respond_success(request_data,
                                         client,
                                         user,
                                         userattrs)

        if 'none' in request_data['prompt']:
            # We were asked to not show any UI
            return self._respond_error(request_data,
                                       'consent_required',
                                       'user interface required')

        # Now ask consent
        if 'form_filled' in kwargs and stage == 'consent':
            # The user has been shown the form, let's process his choice
            if 'decided_allow' in kwargs:
                # User allowed the request
                return self._respond_success(request_data,
                                             client,
                                             user,
                                             userattrs)

            else:
                # User denied consent
                self.debug('User denied consent')
                return self._respond_error(request_data,
                                           'access_denied',
                                           'user denied consent')
        else:
            # The user was not shown the form yet, let's
            data = {'openidc_stage': 'consent',
                    'openidc_request': json.dumps(request_data)}
            self.trans.store(data)

            userattrs = self._source_attributes(us)
            claim_requests = {}
            for claimtype in request_data['claims']:
                for claim in request_data['claims'][claimtype]:
                    if claim in userattrs:
                        essential = False
                        if isinstance(
                                request_data['claims'][claimtype][claim],
                                dict):
                            essential = \
                                request_data['claims'][claimtype][claim].get(
                                    'essential', False)

                        claim_requests[claim] = {
                            'display_name': self.cfg.mapping.display_name(
                                claim),
                            'value': userattrs[claim],
                            'essential': essential
                        }

            scopes = {}
            # Add extension data
            for n, e in self.cfg.extensions.available().items():
                data = e.get_display_data(request_data['scope'])
                self.debug('%s returned %s' % (n, repr(data)))
                if len(data) > 0:
                    scopes[e.get_display_name()] = data

            client_params = {
                'name': client.get('client_name', None),
                'logo': client.get('logo_uri', None),
                'homepage': client.get('client_uri', None),
                'policy': client.get('policy_uri', None),
                'tos': client.get('tos_uri', None)
            }

            if not client_params['name']:
                client_params['name'] = get_url_hostpart(
                    request_data['redirect_uri'])

            context = {
                "title": 'Consent',
                "action": '%s/%s/Continue' % (self.basepath, URLROOT),
                "client": client_params,
                "claim_requests": claim_requests,
                "scopes": scopes,
                "username": user.name,
            }
            context.update(dict((self.trans.get_POST_tuple(),)))
            return self._template(URLROOT + '/consent_form.html', **context)

    def GET(self, *args, **kwargs):
        # We do not pass kwargs in the case of GET, since there
        # will be no arguments passed to this endpoint by GET
        # that we need to process
        return self._perform_continue(*args)

    def POST(self, *args, **kwargs):
        return self._perform_continue(*args, form_filled=True, **kwargs)


class OpenIDC(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(OpenIDC, self).__init__(*args, **kwargs)
        self.Authorization = Authorization(*args, **kwargs)
        self.Continue = Continue(*args, **kwargs)
        self.Token = Token(*args, **kwargs)
        self.TokenInfo = TokenInfo(*args, **kwargs)
        self.Registration = Registration(*args, **kwargs)
        self.UserInfo = UserInfo(*args, **kwargs)

    def wellknown_openid_configuration(self):
        cherrypy.response.headers.update({
            'Content-Type': 'application/json'
        })

        configuration = {
            'issuer': self.cfg.endpoint_url,
            'authorization_endpoint': '%s%s' % (self.cfg.endpoint_url,
                                                'Authorization'),
            'token_endpoint': '%s%s' % (self.cfg.endpoint_url,
                                        'Token'),
            'userinfo_endpoint': '%s%s' % (self.cfg.endpoint_url,
                                           'UserInfo'),
            'jwks_uri': '%s%s' % (self.cfg.endpoint_url,
                                  'Jwks'),
            'scopes_supported': self.cfg.supported_scopes,
            'response_types_supported': ['code', 'id_token' 'token',
                                         'token id_token'],
            'response_modes_supported': ['query', 'fragment', 'form_post',
                                         'none'],
            'grant_types_supported': ['authorization_code', 'implicit',
                                      'refresh_token'],
            'acr_values_supported': ['0'],
            'subject_types_supported': ['pairwise', 'public'],
            # FIXME: At some point, we might want to support all the algorithms
            # that jwcrypto has support for
            'id_token_signing_alg_values_supported': ['RS256'],
            'id_token_encryption_alg_values_supported': [],
            'id_token_encryption_enc_values_supported': [],
            'userinfo_signing_alg_values_supported': ['RS256'],
            'userinfo_encryption_alg_values_supported': [],
            'userinfo_encryption_enc_values_supported': [],
            'request_object_signing_alg_values_supported':
                jws_default_allowed_algs + ['none'],
            'request_object_encryption_alg_values_supported': [],
            'request_object_encryption_enc_values_supported': [],
            'token_endpoint_auth_methods_supported': [
                'client_secret_basic',
                'client_secret_post'
            ],
            'token_endpoint_auth_signing_alg_values_supported': ['RS256'],
            'display_values_supported': ['page', 'popup'],
            'claim_types_supported': ['normal'],
            'claims_supported': [
                'sub', 'name', 'given_name', 'family_name', 'middle_name',
                'nickname', 'preferred_username', 'profile', 'picture',
                'website', 'email', 'email_verified', 'gender', 'birthdate',
                'zoneinfo', 'locale', 'phone_number', 'phone_number_verified',
                'address', 'updated_at'
            ],
            'service_documentation': self.cfg.documentation_url,
            # 'claims_locales_supported': [],
            'ui_locales_supported': ['en'],
            'claims_parameter_supported': True,
            'request_parameter_supported': True,
            'request_uri_parameter_supported': True,
            'require_request_uri_registration': False,
            'op_policy_uri': self.cfg.policy_url,
            'op_tos_uri': self.cfg.tos_url,
        }

        if self.cfg.allow_dynamic_client_registration:
            configuration['registration_endpoint'] = '%s%s' % (
                self.cfg.endpoint_url,
                'Registration')

        return json.dumps(configuration)
    wellknown_openid_configuration.public_function = True

    def Jwks(self):
        cherrypy.response.headers.update({
            'Content-Type': 'application/json'
        })

        # In jwcrypto 0.3.0, JWKSet was changed to be a dict with all the keys
        # in a keys field. Before that, it was a set and we need to loop over
        # the object itself.
        # We can't use the keyset.export function because in 0.2.0 it did not
        # accept an argument to exclude private keys from the export, and there
        # is no way to detect whether we're dealing with 0.3.0 or 0.2.0.
        keyset = self.cfg.keyset
        if isinstance(keyset, dict):
            keyset = keyset['keys']

        keys = []
        for key in keyset:
            keys.append(json.loads(key.export_public()))
        return json.dumps({'keys': keys})
    Jwks.public_function = True

    def __call__(self, *args, **kwargs):
        # We need to have this because it's impossible to have a function
        # called .well-known
        if len(args) == 2 and args == ('.well-known', 'openid-configuration'):
            args = ('wellknown_openid_configuration', )

        return super(OpenIDC, self).__call__(*args, **kwargs)
