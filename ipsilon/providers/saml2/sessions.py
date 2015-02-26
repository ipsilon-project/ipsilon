# Copyright (C) 2015  Rob Crittenden <rcritten@redhat.com>
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

from ipsilon.util.log import Log


class SAMLSession(Log):
    """
    A SAML login session used to track login/logout state.

       session_id - ID of the login session
       provider_id - ID of the SP
       session - the Login session object
       logoutstate - dict containing logout state info
       session_indexes - the IDs of any login session we've seen
                         for this user

    When a new session is seen for the same user any existing session
    is thrown away. We keep the original session_id though and send
    all that we've seen to the SP when performing a logout to ensure
    that all sessions get logged out.

    logout state is a dictionary containing (potentially)
    these attributes:

    relaystate - The relaystate from the Logout Request or Response
    id         - The Logout request id that initiated the logout
    request    - Dump of the initial logout request
    """
    def __init__(self, session_id, provider_id, session,
                 logoutstate=None):

        self.session_id = session_id
        self.provider_id = provider_id
        self.session = session
        self.logoutstate = logoutstate
        self.session_indexes = [session_id]

    def set_logoutstate(self, relaystate, request_id, request=None):
        self.logoutstate = dict(relaystate=relaystate,
                                id=request_id,
                                request=request)

    def dump(self):
        self.debug('session_id %s' % self.session_id)
        self.debug('session_index %s' % self.session_indexes)
        self.debug('provider_id %s' % self.provider_id)
        self.debug('session %s' % self.session)
        self.debug('logoutstate %s' % self.logoutstate)


class SAMLSessionsContainer(Log):
    """
    Store SAML session information.

    The sessions are stored in two dicts which represent the state that
    the session is in.

    When a user logs in, add_session() is called and a new SAMLSession
    created and added to the sessions dict, keyed on provider_id.

    When a user logs out, the next login session is found and moved to
    sessions_logging_out. remove_session() will look in both when trying
    to remove a session.
    """

    def __init__(self):
        self.sessions = dict()
        self.sessions_logging_out = dict()

    def add_session(self, session_id, provider_id, session):
        """
        Add a new session to the logged-in bucket.

        Drop any existing sessions that might exist for this
        provider. We have no control over the SP's so if it sends
        us another login, accept it.

        If an existing session exists drop it but keep a copy of
        its session index. When we logout we send ALL session indexes
        we've received to ensure that they are all logged out.
        """
        samlsession = SAMLSession(session_id, provider_id, session)

        old_session = self.find_session_by_provider(provider_id)
        if old_session is not None:
            samlsession.session_indexes.extend(old_session.session_indexes)
            self.debug("old session: %s" % old_session.session_indexes)
            self.debug("new session: %s" % samlsession.session_indexes)
            self.remove_session_by_provider(provider_id)
        self.sessions[provider_id] = samlsession
        self.dump()

    def remove_session_by_provider(self, provider_id):
        """
        Remove all instances of this provider from either session
        pool.
        """
        if provider_id in self.sessions:
            self.sessions.pop(provider_id)
        if provider_id in self.sessions_logging_out:
            self.sessions_logging_out.pop(provider_id)

    def find_session_by_provider(self, provider_id):
        """
        Return a given session from either pool.

        Return None if no session for a provider is found.
        """
        if provider_id in self.sessions:
            return self.sessions[provider_id]
        if provider_id in self.sessions_logging_out:
            return self.sessions_logging_out[provider_id]
        return None

    def start_logout(self, session):
        """
        Move a session into the logging_out state

        No return value
        """
        if session.provider_id in self.sessions_logging_out:
            return

        session = self.sessions.pop(session.provider_id)

        self.sessions_logging_out[session.provider_id] = session

    def get_next_logout(self):
        """
        Get the next session in the logged-in state and move
        it to the logging_out state.  Return the session that is
        found.

        Return None if no more sessions in login state.
        """
        try:
            provider_id = self.sessions.keys()[0]
        except IndexError:
            return None

        session = self.sessions.pop(provider_id)

        if provider_id in self.sessions_logging_out:
            self.sessions_logging_out.pop(provider_id)

        self.sessions_logging_out[provider_id] = session

        return session

    def get_last_session(self):
        if self.count() != 1:
            raise ValueError('Not exactly one session left')

        try:
            provider_id = self.sessions_logging_out.keys()[0]
        except IndexError:
            return None

        return self.sessions_logging_out.pop(provider_id)

    def count(self):
        """
        Return number of active login/logging out sessions.
        """
        return len(self.sessions) + len(self.sessions_logging_out)

    def dump(self):
        count = 0
        for s in self.sessions:
            self.debug('Login Session: %d' % count)
            session = self.sessions[s]
            session.dump()
            self.debug('-----------------------')
            count += 1
        for s in self.sessions_logging_out:
            self.debug('Logging-out Session: %d' % count)
            session = self.sessions_logging_out[s]
            session.dump()
            self.debug('-----------------------')
            count += 1

if __name__ == '__main__':
    provider1 = "http://127.0.0.10/saml2"
    provider2 = "http://127.0.0.11/saml2"

    saml_sessions = SAMLSessionsContainer()

    try:
        testsession = saml_sessions.get_last_session()
    except ValueError:
        assert(saml_sessions.count() == 0)

    saml_sessions.add_session("_123456",
                              provider1,
                              "sessiondata")

    saml_sessions.add_session("_789012",
                              provider2,
                              "sessiondata")

    try:
        testsession = saml_sessions.get_last_session()
    except ValueError:
        assert(saml_sessions.count() == 2)

    testsession = saml_sessions.find_session_by_provider(provider1)
    assert(testsession.provider_id == provider1)
    assert(testsession.session_id == "_123456")
    assert(testsession.session == "sessiondata")

    # Test get_next_logout() by fetching both values out. Do some
    # basic accounting to ensure we get both values eventually.
    providers = [provider1, provider2]
    testsession = saml_sessions.get_next_logout()
    providers.remove(testsession.provider_id)  # should be one of them

    testsession = saml_sessions.get_next_logout()
    assert(testsession.provider_id == providers[0])  # should be the other

    saml_sessions.start_logout(testsession)
    saml_sessions.remove_session_by_provider(provider2)

    assert(saml_sessions.count() == 1)

    testsession = saml_sessions.get_last_session()
    assert(testsession.provider_id == provider1)

    saml_sessions.remove_session_by_provider(provider1)
    assert(saml_sessions.count() == 0)
