# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

from ipsilon.providers.common import ProviderPageBase
from ipsilon.providers.common import InvalidRequest
from ipsilon.providers.saml2.auth import UnknownProvider
from ipsilon.util.user import UserSession
from ipsilon.util.constants import SOAP_MEDIA_TYPE
import cherrypy
import lasso
import requests


class LogoutRequest(ProviderPageBase):
    """
    SP-initiated logout.

    The sequence is:
      - On each logout a new session is created to represent that
        provider
      - Initial logout request is verified and stored in the login
        session
      - If there are other sessions then one is chosen that is not
        the current provider and a logoutRequest is sent
      - When a logoutResponse is received the session is removed
      - When all other sessions but the initial one have been
        logged out then it a final logoutResponse is sent and the
        session removed. At this point the cherrypy session is
        deleted.
    """

    def __init__(self, site, provider, *args, **kwargs):
        super(LogoutRequest, self).__init__(site, provider)

    def _handle_logout_request(self, us, logout, saml_sessions, message):
        self.debug('Logout request')

        try:
            logout.processRequestMsg(message)
        except (lasso.ServerProviderNotFoundError,
                lasso.ProfileUnknownProviderError) as e:
            msg = 'Invalid SP [%s] (%r [%r])' % (logout.remoteProviderId,
                                                 e, message)
            self.error(msg)
            raise UnknownProvider(msg)
        except lasso.DsInvalidSigalgError as e:
            msg = 'Invalid SAML Request: missing or invalid signature ' \
                  'algorithm'
            self.error(msg)
            raise InvalidRequest(msg)
        except (lasso.ProfileInvalidProtocolprofileError,
                lasso.DsError) as e:
            msg = 'Invalid SAML Request: %r (%r [%r])' % (logout.request,
                                                          e, message)
            self.error(msg)
            raise InvalidRequest(msg)
        except lasso.Error as e:
            self.error('SLO unknown error: %s' % message)
            raise cherrypy.HTTPError(400, 'Invalid logout request')

        session_indexes = logout.request.sessionIndexes
        self.debug('SLO from %s with %s sessions' %
                   (logout.remoteProviderId, session_indexes))

        # Find the first session being asked to log out. Later we loop over
        # all the session indexes and mark them as logging out but only one
        # is needed to handle the request.
        if len(session_indexes) < 1:
            self.error('SLO empty session Indexes')
            raise cherrypy.HTTPError(400, 'Invalid logout request')
        session = saml_sessions.get_session_by_id(session_indexes[0])
        if session:
            try:
                logout.setSessionFromDump(session.login_session)
            except lasso.ProfileBadSessionDumpError as e:
                self.error('loading session failed: %s' % e)
                raise cherrypy.HTTPError(400, 'Invalid logout session')
        else:
            return self._not_logged_in(logout, message)

        try:
            logout.validateRequest()
        except lasso.ProfileSessionNotFoundError as e:
            self.error('Logout failed. No sessions for %s' %
                       logout.remoteProviderId)
            return self._not_logged_in(logout, message)
        except lasso.LogoutUnsupportedProfileError:
            self.error('Logout failed. Unsupported profile %s' %
                       logout.remoteProviderId)
            raise cherrypy.HTTPError(400, 'Profile does not support logout')
        except lasso.Error as e:
            self.error('SLO validation failed: %s' % e)
            raise cherrypy.HTTPError(400, 'Failed to validate logout request')

        try:
            logout.buildResponseMsg()
        except lasso.ProfileUnsupportedProfileError:
            self.error('Unsupported profile for %s' % logout.remoteProviderId)
            raise cherrypy.HTTPError(400, 'Profile does not support logout')
        except lasso.Error as e:
            self.error('SLO failed to build logout response: %s' % e)

        for ind in session_indexes:
            session = saml_sessions.get_session_by_id(ind)
            if session:
                session.set_logoutstate(relaystate=logout.msgUrl,
                                        request=message)
                saml_sessions.start_logout(session)
            else:
                self.error('SLO request to log out non-existent session: %s' %
                           ind)

        return

    def _handle_logout_response(self, us, logout, saml_sessions, message,
                                samlresponse):

        self.debug('Logout response')

        try:
            logout.processResponseMsg(message)
        except lasso.ProfileCannotVerifySignatureError as e:
            msg = 'Invalid or missing signature algorithm %r [%r]' % (
                e, message
            )
            raise InvalidRequest(msg)
        except getattr(lasso, 'ProfileRequestDeniedError',
                       lasso.LogoutRequestDeniedError):
            self.error('Logout request denied by %s' %
                       logout.remoteProviderId)
            # Fall through to next provider
        except (lasso.ProfileInvalidMsgError,
                lasso.LogoutPartialLogoutError) as e:
            self.error('Logout request from %s failed: %s' %
                       (logout.remoteProviderId, e))
        else:
            self.debug('Processing SLO Response from %s' %
                       logout.remoteProviderId)

            self.debug('SLO response to request id %s' %
                       logout.response.inResponseTo)

            session = saml_sessions.get_session_by_request_id(
                logout.response.inResponseTo)

            if session is not None:
                self.debug('Logout response session logout id is: %s' %
                           session.session_id)
                saml_sessions.remove_session(session)
                user = us.get_user()
                self._audit('Logged out user: %s [%s] from %s' %
                            (user.name, user.fullname,
                             logout.remoteProviderId))
            else:
                return self._not_logged_in(logout, message)

        return

    def _not_logged_in(self, logout, message):
        """
        The user requested a logout but isn't logged in, or we can't
        find a session for the user. Try to be nice and redirect them
        back to the RelayState in the logout request.

        We are only nice in the case of a valid logout request. If the
        request is invalid (not signed, unknown SP, etc) then an
        exception is raised.
        """
        self.error('Logout attempt without being logged in.')

        if logout.msgRelayState is not None:
            raise cherrypy.HTTPRedirect(logout.msgRelayState)

        try:
            logout.processRequestMsg(message)
        except lasso.DsInvalidSigalgError as e:
            msg = 'Invalid or missing signature algorithm %r [%r]' % (
                e, message
            )
            raise InvalidRequest(msg)
        except (lasso.ServerProviderNotFoundError,
                lasso.ProfileUnknownProviderError) as e:
            msg = 'Invalid SP [%s] (%r [%r])' % (logout.remoteProviderId,
                                                 e, message)
            self.error(msg)
            raise UnknownProvider(msg)
        except (lasso.ProfileInvalidProtocolprofileError,
                lasso.DsError) as e:
            msg = 'Invalid SAML Request: %r (%r [%r])' % (logout.request,
                                                          e, message)
            self.error(msg)
            raise InvalidRequest(msg)
        except lasso.Error as e:
            self.error('SLO unknown error: %s' % message)
            raise cherrypy.HTTPError(400, 'Invalid logout request')

        if logout.msgRelayState:
            raise cherrypy.HTTPRedirect(logout.msgRelayState)
        else:
            raise cherrypy.HTTPError(400, 'Not logged in')

    def _soap_logout(self, logout):
        """
        Send a SOAP logout request over HTTP and return the result.
        """
        headers = {'Content-Type': SOAP_MEDIA_TYPE}
        try:
            response = requests.post(logout.msgUrl, data=logout.msgBody,
                                     headers=headers)
        except Exception as e:  # pylint: disable=broad-except
            self.error('SOAP HTTP request failed: (%s) (on %s)' %
                       (e, logout.msgUrl))
            raise

        if response.status_code != 200:
            self.error('SOAP error (%s) (on %s)' %
                       (response.status_code, logout.msgUrl))
            raise InvalidRequest('SOAP HTTP error code %s' %
                                 response.status_code)

        if not response.text:
            self.error('Empty SOAP response')
            raise InvalidRequest('No content in SOAP response')

        return response.text

    def logout(self, message, relaystate=None, samlresponse=None):
        """
        Handle HTTP logout. The supported logout methods are stored
        in each session. First all the SOAP sessions are logged out
        then the HTTP Redirect method is used for any remaining
        sessions.

        The basic process is this:
         1. A logout request is received. It is processed and the response
            cached.
         2. If any other SP's have also logged in as this user then the
            first such session is popped off and a logout request is
            generated and forwarded to the SP.
         3. If a logout response is received then the user is marked
            as logged out from that SP.
         Repeat steps 2-3 until only the initial logout request is
         left unhandled, at which time the pre-generated response is sent
         back to the SP that originated the logout request.

        The final logout response is always a redirect.
        """
        logout = self.cfg.idp.get_logout_handler()

        us = UserSession()

        saml_sessions = self.cfg.idp.sessionfactory

        logout_type = None
        try:
            if lasso.SAML2_FIELD_REQUEST in message:
                logout_type = "request"
                self._handle_logout_request(us, logout, saml_sessions,
                                            message)
            elif samlresponse:
                logout_type = "response"
                self._handle_logout_response(us, logout, saml_sessions,
                                             message, samlresponse)
            else:
                raise cherrypy.HTTPError(400, 'Bad Request. Not a ' +
                                         'logout request or response.')
        except InvalidRequest as e:
            raise cherrypy.HTTPError(400, 'Bad Request. %s' % e)
        except UnknownProvider as e:
            raise cherrypy.HTTPError(
                400, 'Invalid logout %s: %s' % (logout_type, e)
            )

        # Fall through to handle any remaining sessions.

        # Find the next SP to logout and send a LogoutRequest
        logout_order = [
            lasso.SAML2_METADATA_BINDING_SOAP,
            lasso.SAML2_METADATA_BINDING_REDIRECT,
        ]
        (logout_mech, session) = saml_sessions.get_next_logout(
            logout_mechs=logout_order, user=us.user)
        while session:
            self.debug('Going to log out %s' % session.provider_id)

            try:
                logout.setSessionFromDump(session.login_session)
            except lasso.ProfileBadSessionDumpError as e:
                self.error('Failed to load session: %s' % e)
                raise cherrypy.HTTPRedirect(400, 'Failed to log out user: %s '
                                            % e)
            try:
                if logout_mech == lasso.SAML2_METADATA_BINDING_REDIRECT:
                    logout.initRequest(session.provider_id,
                                       lasso.HTTP_METHOD_REDIRECT)
                else:
                    logout.initRequest(session.provider_id,
                                       lasso.HTTP_METHOD_SOAP)
            except lasso.ServerProviderNotFoundError:
                self.error(
                    'Service Provider %s not found. Trying next session' %
                    session.provider_id
                )
                saml_sessions.remove_session(session)
                (logout_mech, session) = saml_sessions.get_next_logout(
                    logout_mechs=logout_order, user=us.user)
                continue

            try:
                logout.buildRequestMsg()
            except lasso.Error as e:
                self.error('failure to build logout request msg: %s' % e)
                raise cherrypy.HTTPRedirect(400, 'Failed to log out user: %s '
                                            % e)

            # Set the full list of session indexes for this provider to
            # log out
            self.debug('logging out provider id %s' % session.provider_id)
            indexes = saml_sessions.get_session_id_by_provider_id(
                session.provider_id, us.user
            )
            self.debug('Requesting logout for sessions %s' % (indexes,))
            req = logout.get_request()
            req.setSessionIndexes(indexes)

            session.set_logoutstate(relaystate=logout.msgUrl,
                                    request_id=logout.request.id)
            saml_sessions.start_logout(session, initial=False)

            self.debug('Request logout ID %s for session ID %s' %
                       (logout.request.id, session.session_id))

            if logout_mech == lasso.SAML2_METADATA_BINDING_REDIRECT:
                self.debug('Redirecting to another SP to logout on %s at %s' %
                           (logout.remoteProviderId, logout.msgUrl))
                raise cherrypy.HTTPRedirect(logout.msgUrl)
            else:
                self.debug('SOAP request to another SP to logout on %s at %s' %
                           (logout.remoteProviderId, logout.msgUrl))
                if logout.msgBody:
                    message = self._soap_logout(logout)
                    try:
                        self._handle_logout_response(us,
                                                     logout,
                                                     saml_sessions,
                                                     message,
                                                     samlresponse)
                    except Exception as e:  # pylint: disable=broad-except
                        self.error('SOAP SLO failed %s' % e)
                else:
                    self.error('Provider does not support SOAP')

            (logout_mech, session) = saml_sessions.get_next_logout(
                logout_mechs=logout_order, user=us.user)

        # done while

        # All sessions should be logged out now. Respond to the
        # original request using the response we cached earlier.

        try:
            session = saml_sessions.get_initial_logout(us.user)
        except ValueError:
            self.debug('SLO get_last_session() unable to find last session')
            raise cherrypy.HTTPError(400, 'Unable to determine logout state')

        redirect = session.relaystate
        if not redirect:
            redirect = self.basepath

        saml_sessions.remove_session(session)

        # Log out of cherrypy session
        user = us.get_user()
        self._audit('Logged out user: %s [%s] from %s' %
                    (user.name, user.fullname,
                     session.provider_id))
        us.logout(user)

        self.debug('SLO redirect to %s' % redirect)

        raise cherrypy.HTTPRedirect(redirect)
