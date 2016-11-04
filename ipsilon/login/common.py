# Copyright (C) 2013 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.page import Page
from ipsilon.util.user import UserSession
from ipsilon.util.plugin import PluginInstaller, PluginLoader
from ipsilon.util.plugin import PluginObject
from ipsilon.util.config import ConfigHelper
from ipsilon.info.common import Info
from ipsilon.util.cookies import SecureCookie
from ipsilon.util.log import Log
import cherrypy
import time


USERNAME_COOKIE = 'ipsilon_default_username'


class LoginHelper(Log):

    """Common code supporing login operations.

    Ipsilon can authtenticate a user by itself via it's own login
    handlers (classes derived from `LoginManager`) or it can
    capitalize on the authentication provided by the container Ipsilon
    is running in (currently WSGI inside Apache). We refer to the
    later as "external authentication" because it occurs outside of
    Ipsilon. However in both cases there is a common need to execute
    the same code irregardless of where the authntication
    occurred. This class serves that purpose.
    """

    def get_external_auth_info(self):
        """Return the username and auth type for external authentication.

        If the container Ipsilon is running inside of has already
        authenticated the user prior to reaching one of our endpoints
        return the username and the name of authenticaion method
        used. In Apache this will be REMOTE_USER and AUTH_TYPE.

        The returned auth_type will be prefixed with the string
        "external:" to clearly distinguish between the same method
        being used internally by Ipsilon from the same method used by
        the container hosting Ipsilon. The returned auth_type string
        will be lower case.

        If there was no external authentication both username and
        auth_type will be None. It is possible for a username to be
        returned without knowing the auth_type.

        :return: tuple of (username, auth_type)
        """

        auth_type = None
        username = cherrypy.request.login
        if username:
            auth_type = cherrypy.request.wsgi_environ.get('AUTH_TYPE')
            if auth_type:
                auth_type = 'external:%s' % (auth_type.lower())
                if auth_type == 'external:negotiate' and '@' in username:
                    # This was likely mod_auth_kerb. Let's be compatible with
                    # gssapi
                    cherrypy.request.wsgi_environ['GSS_NAME'] = username
                    username = username[:username.find('@')]

        self.debug("get_external_auth_info: username=%s auth_type=%s" % (
            username, auth_type))

        return username, auth_type

    def initialize_login_session(self, username, info=None,
                                 auth_type=None, userdata=None):
        """Establish a login session for a user.

        Builds a `UserSession` object and bind attributes associated
        with the user to the session.

        User attributes derive from two sources, the `Info` object
        passed as the info parameter and the userdata dict. The `Info`
        object encapsulates the info plugins run by Ipsilon. The
        userdata dict is additional information typically derived
        during authentication.

        The `Info` derived attributes are merged with the userdata
        attributes to form one set of user attributes. The user
        attributes are checked for consistenccy. Additional attrbutes
        may be synthesized and added to the user attributes. The final
        set of user attributes is then bound to the returned
        `UserSession` object.

        :param username:  The username bound to the identity principal
        :param info:      A `Info` object providing user attributes
        :param auth_type: Authenication method name
        :param userdata:  Dict of additional user attributes

        :return: `UserSession` object
        """

        session = UserSession()

        # merge attributes from login plugin and info plugin
        if info:
            infoattrs = info.get_user_attrs(username)
        else:
            infoattrs = dict()

        if userdata is None:
            userdata = dict()

        if '_username' not in userdata:
            userdata['_username'] = username

        if '_groups' in infoattrs:
            userdata['_groups'] = list(set(userdata.get('_groups', []) +
                                           infoattrs['_groups']))
            del infoattrs['_groups']

        if '_extras' in infoattrs:
            userdata['_extras'] = userdata.get('_extras', {})
            userdata['_extras'].update(infoattrs['_extras'])
            del infoattrs['_extras']

        userdata.update(infoattrs)

        self.debug("User %s attributes: %s" % (username, repr(userdata)))

        if auth_type:
            userdata.update({'_auth_type': auth_type})

        userdata.update({'_auth_time': int(time.time())})

        # create session login including all the userdata just gathered
        session.login(username, userdata)

        return session


class LoginManagerBase(ConfigHelper, PluginObject, LoginHelper):

    def __init__(self, *args):
        ConfigHelper.__init__(self)
        PluginObject.__init__(self, *args)
        self._root = None
        self._site = None
        self.path = '/'
        self.info = None

    def redirect_to_path(self, path, trans=None):
        base = cherrypy.config.get('base.mount', "")
        url = '%s/login/%s' % (base, path)
        if trans:
            url += '?%s' % trans.get_GET_arg()
        raise cherrypy.HTTPRedirect(url)

    def auth_successful(self, trans, username, auth_type=None, userdata=None):
        self.initialize_login_session(username, self.info, auth_type, userdata)

        # save username into a cookie if parent was form base auth
        if auth_type == 'password':
            cookie = SecureCookie(USERNAME_COOKIE, username)
            # 15 days
            cookie.maxage = 1296000
            cookie.send()

        transdata = trans.retrieve()
        self.debug(transdata)
        redirect = transdata.get('login_return',
                                 cherrypy.config.get('base.mount', "") + '/')
        self.debug('Redirecting back to: %s' % redirect)

        # on direct login the UI (ie not redirected by a provider) we ned to
        # remove the transaction cookie as it won't be needed anymore
        if trans.provider == 'login':
            self.debug('Wiping transaction data')
            trans.wipe()
        raise cherrypy.HTTPRedirect(redirect)

    def auth_failed(self, trans, message=None):
        # try with next module
        next_login = self.next_login()
        data = {'message': message}
        trans.store(data)
        if next_login:
            return self.redirect_to_path(next_login.path, trans)

        # return to the caller if any
        session = UserSession()

        transdata = trans.retrieve()

        # on direct login the UI (ie not redirected by a provider) we ned to
        # remove the transaction cookie as it won't be needed anymore
        if trans.provider == 'login':
            trans.wipe()

        # destroy session and return error
        if 'login_return' not in transdata:
            session.logout(None)
            raise cherrypy.HTTPError(401, message)

        raise cherrypy.HTTPRedirect(transdata['login_return'])

    def set_auth_error(self):
        cherrypy.response.status = 401

    def get_tree(self, site):
        raise NotImplementedError

    def register(self, root, site):
        self._root = root
        self._site = site

    def next_login(self):
        plugins = self._site[FACILITY]
        try:
            idx = plugins.enabled.index(self.name)
            item = plugins.enabled[idx + 1]
            return plugins.available[item]
        except (ValueError, IndexError):
            return None

    def other_login_stacks(self):
        plugins = self._site[FACILITY]
        stack = list()
        try:
            idx = plugins.enabled.index(self.name)
        except (ValueError, IndexError):
            idx = None
        for i in range(0, len(plugins.enabled)):
            if i == idx:
                continue
            stack.append(plugins.available[plugins.enabled[i]])
        return stack

    def on_enable(self):

        # and add self to the root
        self._root.add_subtree(self.name, self.get_tree(self._site))

        # Get handle of the info plugin
        self.info = self._root.info


class LoginPageBase(Page):

    def __init__(self, site, mgr):
        super(LoginPageBase, self).__init__(site)
        self.lm = mgr
        self._Transaction = None

    def root(self, *args, **kwargs):
        raise cherrypy.HTTPError(500)


class LoginFormBase(LoginPageBase):

    def __init__(self, site, mgr, page, template=None):
        super(LoginFormBase, self).__init__(site, mgr)
        self.formpage = page
        self.formtemplate = template or 'login/form.html'
        self.trans = None

    def GET(self, *args, **kwargs):
        context = self.create_tmpl_context()
        return self._template(self.formtemplate, **context)

    def root(self, *args, **kwargs):
        self.trans = self.get_valid_transaction('login', **kwargs)
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)

    def create_tmpl_context(self, **kwargs):
        other_stacks = None
        other_login_stacks = self.lm.other_login_stacks()
        if other_login_stacks:
            other_stacks = list()
            for ls in other_login_stacks:
                url = '%s/login/%s?%s' % (
                    self.basepath, ls.path, self.trans.get_GET_arg()
                )
                name = ls.name
                other_stacks.append({'url': url, 'name': name})

        cookie = SecureCookie(USERNAME_COOKIE)
        cookie.receive()
        username = cookie.value

        target = None
        if self.trans is not None:
            tid = self.trans.transaction_id
            target = self.trans.retrieve().get('login_target')
            username = self.trans.retrieve().get('login_username')
        if tid is None:
            tid = ''

        if username is None:
            username = ''

        context = {
            "title": 'Login',
            "action": '%s/%s' % (self.basepath, self.formpage),
            "service_name": self.lm.service_name,
            "username_text": self.lm.username_text,
            "password_text": self.lm.password_text,
            "description": self.lm.help_text,
            "other_stacks": other_stacks,
            "username": username,
            "login_target": target,
            "cancel_url": '%s/login/cancel?%s' % (self.basepath,
                                                  self.trans.get_GET_arg()),
        }
        context.update(kwargs)
        if self.trans is not None:
            t = self.trans.get_POST_tuple()
            context.update({t[0]: t[1]})

        return context


FACILITY = 'login_config'


class Login(Page):

    def __init__(self, *args, **kwargs):
        super(Login, self).__init__(*args, **kwargs)
        self.cancel = Cancel(*args, **kwargs)
        self.info = Info(self._site)

        plugins = PluginLoader(Login, FACILITY, 'LoginManager')
        plugins.get_plugin_data()
        self._site[FACILITY] = plugins

        available = plugins.available.keys()
        self.debug('Available login managers: %s' % str(available))

        for item in plugins.available:
            plugin = plugins.available[item]
            plugin.register(self, self._site)

        for item in plugins.enabled:
            self.debug('Login plugin in enabled list: %s' % item)
            if item not in plugins.available:
                continue
            plugins.available[item].enable()

    def add_subtree(self, name, page):
        self.__dict__[name] = page

    def get_first_login(self):
        plugin = None
        plugins = self._site[FACILITY]
        if plugins.enabled:
            first = plugins.enabled[0]
            plugin = plugins.available.get(first)
        return plugin

    def root(self, *args, **kwargs):
        plugin = self.get_first_login()
        if plugin:
            trans = self.get_valid_transaction('login', **kwargs)
            redirect = '%s/login/%s?%s' % (self.basepath,
                                           plugin.path,
                                           trans.get_GET_arg())
            raise cherrypy.HTTPRedirect(redirect)
        return self._template('login/index.html', title='Login')


class Logout(Page):
    def __init__(self, *args, **kwargs):
        super(Logout, self).__init__(*args, **kwargs)
        self.handlers = {}

    def root(self, *args, **kwargs):
        us = UserSession()

        if us.user is not None:
            for provider in self.handlers:
                self.debug("Calling logout for provider %s" % provider)
                obj = self.handlers[provider]
                obj()

        us.logout(self.user)
        return self._template('logout.html', title='Logout')

    def add_handler(self, provider, handler):
        """
        Providers can register a logout handler here that is called
        when the IdP logout link is accessed.
        """
        self.handlers[provider] = handler


class Cancel(Page):

    def GET(self, *args, **kwargs):

        session = UserSession()
        session.logout(None)

        # return to the caller if any
        transdata = self.get_valid_transaction('login', **kwargs).retrieve()
        if 'login_return' not in transdata:
            raise cherrypy.HTTPError(401)
        raise cherrypy.HTTPRedirect(transdata['login_return'])

    def root(self, *args, **kwargs):
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)


class LoginManagerInstaller(object):
    def __init__(self):
        self.facility = FACILITY
        self.ptype = 'login'
        self.name = None

    def unconfigure(self, opts, changes):
        return

    def install_args(self, group):
        raise NotImplementedError

    def validate_args(self, args):
        return

    def configure(self, opts, changes):
        raise NotImplementedError


class LoginMgrsInstall(object):

    def __init__(self):
        pi = PluginInstaller(LoginMgrsInstall, FACILITY)
        self.plugins = pi.get_plugins()
