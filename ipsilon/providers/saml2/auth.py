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
from ipsilon.providers.common import AuthenticationError, InvalidRequest
from ipsilon.providers.saml2.provider import ServiceProvider
from ipsilon.providers.saml2.provider import InvalidProviderId
from ipsilon.providers.saml2.provider import NameIdNotAllowed
from ipsilon.providers.saml2.sessions import SAMLSessionsContainer
from ipsilon.util.policy import Policy
from ipsilon.util.user import UserSession
from ipsilon.util.trans import Transaction
import cherrypy
import datetime
import lasso
import uuid
import hashlib


class UnknownProvider(ProviderException):

    def __init__(self, message):
        super(UnknownProvider, self).__init__(message)
        self._debug(message)


class AuthenticateRequest(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(AuthenticateRequest, self).__init__(*args, **kwargs)
        self.stage = 'init'
        self.trans = None

    def _preop(self, *args, **kwargs):
        try:
            # generate a new id or get current one
            self.trans = Transaction('saml2', **kwargs)
            if self.trans.cookie.value != self.trans.provider:
                self.debug('Invalid transaction, %s != %s' % (
                           self.trans.cookie.value, self.trans.provider))
        except Exception, e:  # pylint: disable=broad-except
            self.debug('Transaction initialization failed: %s' % repr(e))
            raise cherrypy.HTTPError(400, 'Invalid transaction id')

    def pre_GET(self, *args, **kwargs):
        self._preop(*args, **kwargs)

    def pre_POST(self, *args, **kwargs):
        self._preop(*args, **kwargs)

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

        us = UserSession()
        user = us.get_user()
        if user.is_anonymous:
            if self.stage == 'init':
                returl = '%s/saml2/SSO/Continue?%s' % (
                    self.basepath, self.trans.get_GET_arg())
                data = {'saml2_stage': 'auth',
                        'saml2_request': login.dump(),
                        'login_return': returl,
                        'login_target': login.remoteProviderId}
                self.trans.store(data)
                redirect = '%s/login?%s' % (self.basepath,
                                            self.trans.get_GET_arg())
                raise cherrypy.HTTPRedirect(redirect)
            else:
                raise AuthenticationError(
                    "Unknown user", lasso.SAML2_STATUS_CODE_AUTHN_FAILED)

        self._audit("Logged in user: %s [%s]" % (user.name, user.fullname))

        # We can wipe the transaction now, as this is the last step
        self.trans.wipe()

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
            idpsalt = self.cfg.idp_nameid_salt
            if idpsalt is None:
                raise AuthenticationError(
                    "idp nameid salt is not set in configuration"
                )
            value = hashlib.sha512()
            value.update(idpsalt)
            value.update(login.remoteProviderId)
            value.update(user.name)
            nameid = '_' + value.hexdigest()
        elif nameidfmt == lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT:
            nameid = '_' + uuid.uuid4().hex
        elif nameidfmt == lasso.SAML2_NAME_IDENTIFIER_FORMAT_KERBEROS:
            nameid = us.get_data('user', 'gssapi_principal_name')
        elif nameidfmt == lasso.SAML2_NAME_IDENTIFIER_FORMAT_EMAIL:
            nameid = us.get_user().email
            if not nameid:
                nameid = '%s@%s' % (user.name, self.cfg.default_email_domain)
        elif nameidfmt == lasso.SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED:
            nameid = provider.normalize_username(user.name)

        if nameid:
            login.assertion.subject.nameId.format = nameidfmt
            login.assertion.subject.nameId.content = nameid
        else:
            self.trans.wipe()
            raise AuthenticationError("Unavailable Name ID type",
                                      lasso.SAML2_STATUS_CODE_AUTHN_FAILED)

        # Check attribute policy and perform mapping and filtering.
        # If the SP has its own mapping or filtering policy use that
        # instead of the global policy.
        if (provider.attribute_mappings is not None and
                len(provider.attribute_mappings) > 0):
            attribute_mappings = provider.attribute_mappings
        else:
            attribute_mappings = self.cfg.default_attribute_mapping
        if (provider.allowed_attributes is not None and
                len(provider.allowed_attributes) > 0):
            allowed_attributes = provider.allowed_attributes
        else:
            allowed_attributes = self.cfg.default_allowed_attributes
        self.debug("Allowed attrs: %s" % allowed_attributes)
        self.debug("Mapping: %s" % attribute_mappings)
        policy = Policy(attribute_mappings, allowed_attributes)
        userattrs = us.get_user_attrs()
        mappedattrs, _ = policy.map_attributes(userattrs)
        attributes = policy.filter_attributes(mappedattrs)

        if '_groups' in attributes and 'groups' not in attributes:
            attributes['groups'] = attributes['_groups']

        self.debug("%s's attributes: %s" % (user.name, attributes))

        # The saml-core-2.0-os specification section 2.7.3 requires
        # the AttributeStatement element to be non-empty.
        if attributes:
            if not login.assertion.attributeStatement:
                attrstat = lasso.Saml2AttributeStatement()
                login.assertion.attributeStatement = [attrstat]
            else:
                attrstat = login.assertion.attributeStatement[0]
            if not attrstat.attribute:
                attrstat.attribute = ()

        for key in attributes:
            # skip internal info
            if key[0] == '_':
                continue
            values = attributes[key]
            if isinstance(values, dict):
                continue
            if not isinstance(values, list):
                values = [values]
            for value in values:
                attr = lasso.Saml2Attribute()
                attr.name = key
                attr.nameFormat = lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC
                value = str(value).encode('utf-8')
                self.debug('value %s' % value)
                node = lasso.MiscTextNode.newWithString(value)
                node.textChild = True
                attrvalue = lasso.Saml2AttributeValue()
                attrvalue.any = [node]
                attr.attributeValue = [attrvalue]
                attrstat.attribute = attrstat.attribute + (attr,)

        self.debug('Assertion: %s' % login.assertion.dump())

        saml_sessions = us.get_provider_data('saml2')
        if saml_sessions is None:
            saml_sessions = SAMLSessionsContainer()

        session = saml_sessions.find_session_by_provider(
            login.remoteProviderId)
        if session:
            # TODO: something...
            self.debug('Login session for this user already exists!?')
            session.dump()

        lasso_session = lasso.Session()
        lasso_session.addAssertion(login.remoteProviderId, login.assertion)
        saml_sessions.add_session(login.assertion.id,
                                  login.remoteProviderId,
                                  lasso_session)
        us.save_provider_data('saml2', saml_sessions)

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
