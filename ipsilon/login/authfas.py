#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon contributors, see COPYING file for license


from ipsilon.info.common import InfoMapping
from ipsilon.login.common import LoginFormBase, LoginManagerBase
from ipsilon.login.common import FACILITY
from ipsilon.util.plugin import PluginObject
import cherrypy

from fedora.client.fasproxy import FasProxyClient
from fedora.client import AuthError


try:
    import openid_cla.cla as cla

    CLA_GROUPS = {
        'cla_click': cla.CLA_URI_FEDORA_CLICK,
        'cla_dell': cla.CLA_URI_FEDORA_DELL,
        'cla_done': cla.CLA_URI_FEDORA_DONE,
        'cla_fedora': cla.CLA_URI_FEDORA_FEDORA,
        'cla_fpca': cla.CLA_URI_FEDORA_FPCA,
        'cla_ibm': cla.CLA_URI_FEDORA_IBM,
        'cla_intel': cla.CLA_URI_FEDORA_INTEL,
        'cla_redhat': cla.CLA_URI_FEDORA_REDHAT,
    }
except ImportError:
    CLA_GROUPS = dict()

fas_mapping = {
    'username': 'nickname',
    'telephone': 'phone',
    'country_code': 'country',
    'human_name': 'fullname',
    'email': 'email',
    'timezone': 'timezone',
}


class FAS(LoginFormBase):

    def __init__(self, site, mgr, page):
        super(FAS, self).__init__(site, mgr, page)
        self.mapper = InfoMapping()
        self.mapper.set_mapping(fas_mapping)

    def POST(self, *args, **kwargs):
        username = kwargs.get("login_name")
        password = kwargs.get("login_password")
        error = None

        if username and password:
            data = None
            try:
                _, data = self.lm.fpc.login(username, password)
            except AuthError, e:
                cherrypy.log.error("Authentication error [%s]" % str(e))
            except Exception, e:  # pylint: disable=broad-except
                cherrypy.log.error("Unknown Error [%s]" % str(e))
            if data and data.user:
                userdata = self.make_userdata(data.user)
                return self.lm.auth_successful(self.trans,
                                               data.user['username'],
                                               userdata=userdata)
            else:
                error = "Authentication failed"
                cherrypy.log.error(error)
        else:
            error = "Username or password is missing"
            cherrypy.log.error("Error: " + error)

        context = self.create_tmpl_context(
            username=username,
            error=error,
            error_password=not password,
            error_username=not username
        )
        # pylint: disable=star-args
        return self._template(self.formtemplate, **context)

    def make_userdata(self, fas_data):
        userdata, fas_extra = self.mapper.map_attrs(fas_data)

        # compute and store groups and cla groups
        userdata['groups'] = []
        userdata['extras'] = {'fas': fas_extra, 'cla': []}
        for group in fas_data.get('approved_memberships', {}):
            if 'name' not in group:
                continue
            if group.get('group_type') == 'cla':
                if group['name'] in CLA_GROUPS:
                    userdata['extras']['cla'].append(CLA_GROUPS[group['name']])
                else:
                    userdata['extras']['cla'].append(group['name'])
            else:
                userdata['groups'].append(group['name'])

        return userdata


class LoginManager(LoginManagerBase):

    def __init__(self, *args, **kwargs):
        super(LoginManager, self).__init__(*args, **kwargs)
        self.name = 'fas'
        self.path = 'fas'
        self.service_name = 'fas'
        self.page = None
        self.fpc = None
        self.description = """
Form based login Manager that uses the Fedora Authentication Server
"""
        self._options = {
            'help text': [
                """ The text shown to guide the user at login time. """,
                'string',
                'Login wth your FAS credentials'
            ],
            'username text': [
                """ The text shown to ask for the username in the form. """,
                'string',
                'FAS Username'
            ],
            'password text': [
                """ The text shown to ask for the password in the form. """,
                'string',
                'Password'
            ],
            'FAS url': [
                """ The FAS Url. """,
                'string',
                'https://admin.fedoraproject.org/accounts/'
            ],
            'FAS Proxy client user Agent': [
                """ The User Agent presented to the FAS Server. """,
                'string',
                'Ipsilon v1.0'
            ],
            'FAS Insecure Auth': [
                """ If 'YES' skips FAS server cert verification. """,
                'string',
                ''
            ],
        }
        self.conf_opt_order = ['FAS url', 'FAS Proxy client user Agent',
                               'FAS Insecure Auth', 'username text',
                               'password text', 'help text']

    @property
    def help_text(self):
        return self.get_config_value('help text')

    @property
    def username_text(self):
        return self.get_config_value('username text')

    @property
    def password_text(self):
        return self.get_config_value('password text')

    @property
    def fas_url(self):
        return self.get_config_value('FAS url')

    @property
    def user_agent(self):
        return self.get_config_value('FAS Proxy client user Agent')

    @property
    def insecure(self):
        return self.get_config_value('FAS Insecure Auth')

    def get_tree(self, site):
        self.fpc = FasProxyClient(base_url=self.fas_url,
                                  useragent=self.user_agent,
                                  insecure=(self.insecure == 'YES'))
        self.page = FAS(site, self, 'login/fas')
        return self.page


class Installer(object):

    def __init__(self):
        self.name = 'fas'
        self.ptype = 'login'

    def install_args(self, group):
        group.add_argument('--fas', choices=['yes', 'no'], default='no',
                           help='Configure FAS authentication')

    def configure(self, opts):
        if opts['fas'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject()
        po.name = 'fas'
        po.wipe_data()

        po.wipe_config_values(FACILITY)

        # Update global config to add login plugin
        po = PluginObject()
        po.name = 'global'
        globalconf = po.get_plugin_config(FACILITY)
        if 'order' in globalconf:
            order = globalconf['order'].split(',')
        else:
            order = []
        order.append('fas')
        globalconf['order'] = ','.join(order)
        po.set_config(globalconf)
        po.save_plugin_config(FACILITY)
