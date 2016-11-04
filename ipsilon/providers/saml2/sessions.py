# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

from cherrypy import config as cherrypy_config
from ipsilon.util.log import Log
from ipsilon.util.data import SAML2SessionStore
from lasso import (
    SAML2_METADATA_BINDING_SOAP,
    SAML2_METADATA_BINDING_REDIRECT,
)

LOGGED_IN = 1
INIT_LOGOUT = 2
LOGGING_OUT = 4
LOGGED_OUT = 8


class SAMLSession(Log):
    """
    A SAML login session.

       uuidval - Unique ID stored in the database
       session_id - ID of the login session
       provider_id - ID of the SP
       user - the login name of the user that owns the session
       login_session - the Login session object
       logoutstate - an integer constant representing where in the
                     logout process this request is
       relaystate - where the user will be redirected when logout is
                    complete
       request_id - the logout request ID if initiated from IdP. The
                    logout response will include an InResponseTo value
                    which matches this.
       logout_request - the Logout request object
       supported_logout_mechs - logout mechanisms supported by this session
    """
    def __init__(self, uuidval, session_id, provider_id, user,
                 login_session, logoutstate=None, relaystate=None,
                 logout_request=None, request_id=None,
                 supported_logout_mechs=None):

        self.uuidval = uuidval
        self.session_id = session_id
        self.provider_id = provider_id
        self.user = user
        self.login_session = login_session
        self.logoutstate = logoutstate
        self.relaystate = relaystate
        self.request_id = request_id
        self.logout_request = logout_request
        if supported_logout_mechs is None:
            supported_logout_mechs = []
        self.supported_logout_mechs = supported_logout_mechs

    def set_logoutstate(self, relaystate=None, request=None, request_id=None):
        """
        Update attributes needed to determine the state of the session for
        logout.

        The database is not updated when these are set. It is expected that
        this is called prior to start_logout()
        """
        if relaystate:
            self.relaystate = relaystate
        if request:
            self.logout_request = request
        if request_id:
            self.request_id = request_id

    def dump(self):
        self.debug('session_id %s' % self.session_id)
        self.debug('provider_id %s' % self.provider_id)
        self.debug('login session %s' % self.login_session)
        self.debug('logoutstate %s' % self.logoutstate)
        self.debug('logout mech %s' % self.supported_logout_mechs)

    def convert(self):
        """
        Convert this object into something suitable to store in the
        data backend.
        """
        data = dict()
        data['session_id'] = self.session_id
        data['provider_id'] = self.provider_id
        data['user'] = self.user
        data['login_session'] = self.login_session
        data['logoutstate'] = self.logoutstate
        data['relaystate'] = self.relaystate
        data['logout_request'] = self.logout_request
        data['request_id'] = self.request_id

        return {self.uuidval: data}


class SAMLSessionFactory(Log):
    """
    Access SAML session information.

    The sessions are stored via the data backend.

    When a user logs in, add_session() is called and a new SAMLSession
    created and added to the table.

    When a user logs out, the next login session is found and moved to
    sessions_logging_out. remove_session() will look in both when trying
    to remove a session.

    Returns a SAMLSession object representing the new session.
    """
    def __init__(self, database_url):
        self._ss = SAML2SessionStore(database_url=database_url)

    def _data_to_samlsession(self, uuidval, data):
        """
        Convert data from the data backend to a SAMLSession object.
        """
        return SAMLSession(uuidval,
                           data.get('session_id'),
                           data.get('provider_id'),
                           data.get('user'),
                           data.get('login_session'),
                           data.get('logoutstate'),
                           data.get('relaystate'),
                           data.get('logout_request'),
                           data.get('request_id'),
                           data.get('supported_logout_mechs'))

    def add_session(self, session_id, provider_id, user, login_session,
                    request_id, supported_logout_mechs):
        """
        Add a new login session to the table.

        :param session_id: The login session ID
        :param provider_id: The URL of the SP
        :param user: The NameID username
        :param login_session: The lasso Login session
        :param request_id: The request ID of the Logout
        :param supported_logout_mechs: A list of logout protocols supported
        """
        ttl = cherrypy_config['tools.sessions.timeout'] * 60

        data = {'session_id': session_id,
                'provider_id': provider_id,
                'user': user,
                'login_session': login_session,
                'logoutstate': LOGGED_IN,
                'request_id': request_id,
                'supported_logout_mechs': supported_logout_mechs}

        uuidval = self._ss.new_session(data, ttl)

        return SAMLSession(uuidval, session_id, provider_id, user,
                           login_session, LOGGED_IN,
                           request_id=request_id)

    def get_session_by_id(self, session_id):
        """
        Retrieve a session by session ID
        """
        uuidval, data = self._ss.get_session(session_id=session_id)
        if uuidval is None:
            return None

        return self._data_to_samlsession(uuidval, data)

    def get_session_id_by_provider_id(self, provider_id, user):
        """
        Return a tuple of logged-in session IDs by provider_id
        """
        candidates = self._ss.get_user_sessions(user)

        session_ids = []
        for c in candidates:
            key = c.keys()[0]
            if c[key].get('provider_id') == provider_id:
                samlsession = self._data_to_samlsession(key, c[key])
                session_ids.append(samlsession.session_id.encode('utf-8'))

        return tuple(session_ids)

    def get_session_by_request_id(self, request_id):
        """
        Retrieve a session by logout request ID
        """
        uuidval, data = self._ss.get_session(request_id=request_id)
        if uuidval is None:
            return None

        return self._data_to_samlsession(uuidval, data)

    def remove_session(self, samlsession):
        return self._ss.remove_session(samlsession.uuidval)

    def remove_session_by_session_id(self, session_id):
        session = self.get_session_by_id(session_id)
        return self._ss.remove_session(session.uuidval)

    def start_logout(self, samlsession, relaystate=None, initial=True):
        """
        Move a session into the logging_out state

        samlsession: the SAMLSession object to start logging out
        relaystate: URL to redirect user to when logout is completed
        initial: boolean to indicate if this session started logout.
                 Only the initial session's relaystate is used.

        No return value
        """
        if initial:
            samlsession.logoutstate = INIT_LOGOUT
        else:
            samlsession.logoutstate = LOGGING_OUT
        if relaystate:
            samlsession.relaystate = relaystate
        datum = samlsession.convert()
        self._ss.update_session(datum)

    def get_next_logout(self, peek=False,
                        logout_mechs=None, user=None):
        """
        Get the next session in the logged-in state and move
        it to the logging_out state.  Return the session that is
        found.

        :param peek: for IdP-initiated logout we can't remove the
                     session otherwise when the request comes back
                     in the user won't be seen as being logged-on.
        :param logout_mechs: An ordered list of logout mechanisms
                     you're looking for. For each mechanism in order
                     loop through all sessions. If If no sessions of
                     this method are available then try the next mechanism
                     until exhausted. In that case None is returned.

        Returns a tuple of (mechanism, session) or
        (None, None) if no more sessions in LOGGED_IN state.
        """
        candidates = self._ss.get_user_sessions(user)
        if logout_mechs is None:
            logout_mechs = [SAML2_METADATA_BINDING_REDIRECT, ]

        for mech in logout_mechs:
            for c in candidates:
                key = c.keys()[0]
                if ((int(c[key].get('logoutstate', 0)) == LOGGED_IN) and
                        (mech in c[key].get('supported_logout_mechs'))):
                    samlsession = self._data_to_samlsession(key, c[key])
                    self.start_logout(samlsession, initial=False)
                    return (mech, samlsession)
        return (None, None)

    def get_initial_logout(self, user):
        """
        Get the initial logout request.

        Raises ValueError if no sessions in INIT_LOGOUT state.
        """
        candidates = self._ss.get_user_sessions(user)

        # FIXME: what does it mean if there are multiple in init? We
        #        just return the first one for now. How do we know
        #        it's the "right" one if multiple logouts are started
        #        at the same time from different SPs?
        for c in candidates:
            key = c.keys()[0]
            if int(c[key].get('logoutstate', 0)) == INIT_LOGOUT:
                samlsession = self._data_to_samlsession(key, c[key])
                return samlsession
        raise ValueError()

    def wipe_data(self):
        self._ss.wipe_data()

    def dump(self, user):
        """
        Dump all sessions to debug log
        """
        candidates = self._ss.get_user_sessions(user)

        count = 0
        for c in candidates:
            key = c.keys()[0]
            samlsession = self._data_to_samlsession(key, c[key])
            self.debug('session %d: %s' % (count, samlsession.convert()))
            count += 1

if __name__ == '__main__':
    provider1 = "http://127.0.0.10/saml2"
    provider2 = "http://127.0.0.11/saml2"

    # temporary values to simulate cherrypy
    cherrypy_config['tools.sessions.timeout'] = 60

    factory = SAMLSessionFactory('/tmp/saml2sessions.sqlite')
    factory.wipe_data()

    sess1 = factory.add_session('_123456', provider1, "admin",
                                "<Login/>", '_1234',
                                [SAML2_METADATA_BINDING_REDIRECT])
    sess2 = factory.add_session('_789012', provider2, "testuser",
                                "<Login/>", '_7890',
                                [SAML2_METADATA_BINDING_SOAP,
                                 SAML2_METADATA_BINDING_REDIRECT])

    # Test finding sessions by provider
    ids = factory.get_session_id_by_provider_id(provider2, user='admin')
    assert(len(ids) == 1)

    sess3 = factory.add_session('_345678', provider2, "testuser",
                                "<Login/>", '_3456',
                                [SAML2_METADATA_BINDING_REDIRECT])
    ids = factory.get_session_id_by_provider_id(provider2, user='testuser')
    assert(len(ids) == 2)

    # Test finding sessions by session ID
    test1 = factory.get_session_by_id('_123456')
    assert(test1.user == 'admin')
    assert(test1.provider_id == provider1)

    # Log out and remove the first session
    test1.set_logoutstate('http://www.example.com/idp')
    factory.start_logout(test1, initial=True)
    test1 = factory.get_session_by_id('_123456')
    assert(test1.relaystate == 'http://www.example.com/idp')

    factory.remove_session_by_session_id('_123456')

    # Make sure it is gone from the db
    test1 = factory.get_session_by_id('_123456')
    assert(test1 is None)

    test2 = factory.get_session_by_id('_789012')
    factory.start_logout(test2, initial=True)

    (lmech, test3) = factory.get_next_logout(user='admin')
    assert(test3.session_id == '_345678')

    test4 = factory.get_initial_logout(user='admin')
    assert(test4.session_id == '_789012')

    # Even though we've started logout, make sure we can still find
    # all sessions for a provider.
    ids = factory.get_session_id_by_provider_id(provider2, user='admin')
    assert(len(ids) == 2)
