#!/usr/bin/python
#
# Copyright (C) 2014  Simo Sorce <simo@redhat.com>
#
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from ipsilon.providers.common import ProviderPageBase, ProviderException
from ipsilon.providers.saml2.provider import ServiceProvider
from ipsilon.providers.saml2.provider import InvalidProviderId
from ipsilon.providers.saml2.provider import NameIdNotAllowed
from ipsilon.util.user import UserSession
import cherrypy
import datetime
import lasso


class AuthenticationError(ProviderException):

    def __init__(self, message, code):
        super(AuthenticationError, self).__init__(message)
        self.code = code
        self._debug('%s [%s]' % (message, code))


class InvalidRequest(ProviderException):

    def __init__(self, message):
        super(InvalidRequest, self).__init__(message)
        self._debug(message)


class UnknownProvider(ProviderException):

    def __init__(self, message):
        super(UnknownProvider, self).__init__(message)
        self._debug(message)


class AuthenticateRequest(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(AuthenticateRequest, self).__init__(*args, **kwargs)
        self.STAGE_INIT = 0
        self.STAGE_AUTH = 1
        self.stage = self.STAGE_INIT

    def auth(self, login):
        try:
            self.saml2checks(login)
        except AuthenticationError, e:
            self.saml2error(login, e.code, e.message)
        return self.reply(login)

    def _parse_request(self, message):

        login = self.cfg.idp.get_login_handler()

        try:
            login.processAuthnRequestMsg(message)
        except (lasso.ProfileInvalidMsgError,
                lasso.ProfileMissingIssuerError), e:

            msg = 'Malformed Request %r [%r]' % (e, message)
            raise InvalidRequest(msg)

        except (lasso.ProfileInvalidProtocolprofileError,
                lasso.DsError), e:

            msg = 'Invalid SAML Request: %r (%r [%r])' % (login.request,
                                                          e, message)
            raise InvalidRequest(msg)

        except (lasso.ServerProviderNotFoundError,
                lasso.ProfileUnknownProviderError), e:

            msg = 'Invalid SP [%s] (%r [%r])' % (login.remoteProviderId,
                                                 e, message)
            raise UnknownProvider(msg)

        self._debug('SP %s requested authentication' % login.remoteProviderId)

        return login

    def saml2login(self, request):

        if not request:
            raise cherrypy.HTTPError(400,
                                     'SAML request token missing or empty')

        try:
            login = self._parse_request(request)
        except InvalidRequest, e:
            self._debug(str(e))
            raise cherrypy.HTTPError(400, 'Invalid SAML request token')
        except UnknownProvider, e:
            self._debug(str(e))
            raise cherrypy.HTTPError(400, 'Unknown Service Provider')
        except Exception, e:  # pylint: disable=broad-except
            self._debug(str(e))
            raise cherrypy.HTTPError(500)

        return login

    def saml2checks(self, login):

        session = UserSession()
        user = session.get_user()
        if user.is_anonymous:
            if self.stage < self.STAGE_AUTH:
                session.save_data('saml2', 'stage', self.STAGE_AUTH)
                session.save_data('saml2', 'Request', login.dump())
                session.save_data('login', 'Return',
                                  '%s/saml2/SSO/Continue' % self.basepath)
                raise cherrypy.HTTPRedirect('%s/login' % self.basepath)
            else:
                raise AuthenticationError(
                    "Unknown user", lasso.SAML2_STATUS_CODE_AUTHN_FAILED)

        self._audit("Logged in user: %s [%s]" % (user.name, user.fullname))

        # TODO: check if this is the first time this user access this SP
        # If required by user prefs, ask user for consent once and then
        # record it
        consent = True

        # TODO: check destination

        try:
            provider = ServiceProvider(self.cfg, login.remoteProviderId)
            nameidfmt = provider.get_valid_nameid(login.request.nameIdPolicy)
        except NameIdNotAllowed, e:
            raise AuthenticationError(
                str(e), lasso.SAML2_STATUS_CODE_INVALID_NAME_ID_POLICY)
        except InvalidProviderId, e:
            raise AuthenticationError(
                str(e), lasso.SAML2_STATUS_CODE_AUTHN_FAILED)

        # TODO: check login.request.forceAuthn

        login.validateRequestMsg(not user.is_anonymous, consent)

        authtime = datetime.datetime.utcnow()
        skew = datetime.timedelta(0, 60)
        authtime_notbefore = authtime - skew
        authtime_notafter = authtime + skew

        us = UserSession()
        user = us.get_user()

        # TODO: get authentication type fnd name format from session
        # need to save which login manager authenticated and map it to a
        # saml2 authentication context
        authn_context = lasso.SAML2_AUTHN_CONTEXT_UNSPECIFIED

        timeformat = '%Y-%m-%dT%H:%M:%SZ'
        login.buildAssertion(authn_context,
                             authtime.strftime(timeformat),
                             None,
                             authtime_notbefore.strftime(timeformat),
                             authtime_notafter.strftime(timeformat))

        nameid = None
        if nameidfmt == lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT:
            # TODO map to something else ?
            nameid = provider.normalize_username(user.name)
        elif nameidfmt == lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT:
            # TODO map to something else ?
            nameid = provider.normalize_username(user.name)
        elif nameidfmt == lasso.SAML2_NAME_IDENTIFIER_FORMAT_KERBEROS:
            nameid = us.get_data('user', 'krb_principal_name')
        elif nameidfmt == lasso.SAML2_NAME_IDENTIFIER_FORMAT_EMAIL:
            nameid = us.get_user().email
            if not nameid:
                nameid = '%s@%s' % (user.name, self.cfg.default_email_domain)

        if nameid:
            login.assertion.subject.nameId.format = nameidfmt
            login.assertion.subject.nameId.content = nameid
        else:
            raise AuthenticationError("Unavailable Name ID type",
                                      lasso.SAML2_STATUS_CODE_AUTHN_FAILED)

        # TODO: add user attributes as policy requires from 'usersession'

    def saml2error(self, login, code, message):
        status = lasso.Samlp2Status()
        status.statusCode = lasso.Samlp2StatusCode()
        status.statusCode.value = lasso.SAML2_STATUS_CODE_RESPONDER
        status.statusCode.statusCode = lasso.Samlp2StatusCode()
        status.statusCode.statusCode.value = code
        login.response.status = status

    def reply(self, login):
        if login.protocolProfile == lasso.LOGIN_PROTOCOL_PROFILE_BRWS_ART:
            # TODO
            raise cherrypy.HTTPError(501)
        elif login.protocolProfile == lasso.LOGIN_PROTOCOL_PROFILE_BRWS_POST:
            login.buildAuthnResponseMsg()
            self._debug('POSTing back to SP [%s]' % (login.msgUrl))
            context = {
                "title": 'Redirecting back to the web application',
                "action": login.msgUrl,
                "fields": [
                    [lasso.SAML2_FIELD_RESPONSE, login.msgBody],
                    [lasso.SAML2_FIELD_RELAYSTATE, login.msgRelayState],
                ],
                "submit": 'Return to application',
            }
            # pylint: disable=star-args
            return self._template('saml2/post_response.html', **context)

        else:
            raise cherrypy.HTTPError(500)
