# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.providers.common import ProviderPageBase
from ipsilon.util.user import UserSession
from ipsilon.util.endpoint import allow_iframe

import base64
import cherrypy
import time
import json
import M2Crypto


class AuthenticateRequest(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(AuthenticateRequest, self).__init__(*args, **kwargs)
        self.trans = None

    def _preop(self, *args, **kwargs):
        self.trans = self.get_valid_transaction('persona', **kwargs)

    def pre_GET(self, *args, **kwargs):
        self._preop(*args, **kwargs)

    def pre_POST(self, *args, **kwargs):
        self._preop(*args, **kwargs)


class Sign(AuthenticateRequest):

    def _base64_url_decode(self, inp):
        inp += '=' * (4 - (len(inp) % 4))
        return base64.urlsafe_b64decode(inp)

    def _base64_url_encode(self, inp):
        return base64.urlsafe_b64encode(inp).replace('=', '')

    def _persona_sign(self, email, publicKey, certDuration):
        self.debug('Signing for %s with duration of %s' % (email,
                                                           certDuration))
        header = {'alg': 'RS256'}
        header = json.dumps(header)
        header = self._base64_url_encode(header)

        claim = {}
        # Valid from 10 seconds before now to account for clock skew
        claim['iat'] = 1000 * int(time.time() - 10)
        # Validity of at most 24 hours
        claim['exp'] = 1000 * int(time.time() +
                                  min(certDuration, 24 * 60 * 60))

        claim['iss'] = self.cfg.issuer_domain
        claim['public-key'] = json.loads(publicKey)
        claim['principal'] = {'email': email}

        claim = json.dumps(claim)
        claim = self._base64_url_encode(claim)

        certificate = '%s.%s' % (header, claim)
        digest = M2Crypto.EVP.MessageDigest('sha256')
        digest.update(certificate)
        signature = self.cfg.key.sign(digest.digest(), 'sha256')
        signature = self._base64_url_encode(signature)
        signed_certificate = '%s.%s' % (certificate, signature)

        return signed_certificate

    def _willing_to_sign(self, email, username):
        for domain in self.cfg.allowed_domains:
            if email == ('%s@%s' % (username, domain)):
                return True
        return False

    @allow_iframe
    def POST(self, *args, **kwargs):
        if 'email' not in kwargs or 'publicKey' not in kwargs \
                or 'certDuration' not in kwargs or '@' not in kwargs['email']:
            cherrypy.response.status = 400
            raise Exception('Invalid request: %s' % kwargs)

        us = UserSession()
        user = us.get_user()

        if user.is_anonymous:
            raise cherrypy.HTTPError(401, 'Not signed in')

        if not self._willing_to_sign(kwargs['email'], user.name):
            self.log('Not willing to sign for %s, logged in as %s' % (
                kwargs['email'], user.name))
            raise cherrypy.HTTPError(403, 'Incorrect user')

        return self._persona_sign(kwargs['email'], kwargs['publicKey'],
                                  kwargs['certDuration'])


class SignInResult(AuthenticateRequest):
    @allow_iframe
    def GET(self, *args, **kwargs):
        user = UserSession().get_user()

        return self._template('persona/signin_result.html',
                              loggedin=not user.is_anonymous)


class SignIn(AuthenticateRequest):
    def __init__(self, *args, **kwargs):
        super(SignIn, self).__init__(*args, **kwargs)
        self.result = SignInResult(*args, **kwargs)
        self.trans = None

    @allow_iframe
    def GET(self, *args, **kwargs):
        username = None
        domain = None
        if 'email' in kwargs:
            if '@' in kwargs['email']:
                username, domain = kwargs['email'].split('@', 2)
                self.debug('Persona SignIn requested for: %s@%s' % (username,
                                                                    domain))

        returl = '%s/persona/SignIn/result?%s' % (
            self.basepath, self.trans.get_GET_arg())
        data = {'login_return': returl,
                'login_target': 'Persona',
                'login_username': username}
        self.trans.store(data)
        redirect = '%s/login?%s' % (self.basepath,
                                    self.trans.get_GET_arg())
        self.debug('Redirecting: %s' % redirect)
        raise cherrypy.HTTPRedirect(redirect)


class Persona(AuthenticateRequest):

    def __init__(self, *args, **kwargs):
        super(Persona, self).__init__(*args, **kwargs)
        self.Sign = Sign(*args, **kwargs)
        self.SignIn = SignIn(*args, **kwargs)
        self.trans = None

    @allow_iframe
    def GET(self, *args, **kwargs):
        user = UserSession().get_user()
        return self._template('persona/provisioning.html',
                              loggedin=not user.is_anonymous)
