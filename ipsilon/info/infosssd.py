# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

# Info plugin for mod_lookup_identity Apache module via SSSD
# http://www.adelton.com/apache/mod_lookup_identity/

from ipsilon.info.common import InfoProviderBase
from ipsilon.info.common import InfoProviderInstaller
from ipsilon.util.plugin import PluginObject
from ipsilon.util.policy import Policy
from ipsilon.util import config as pconfig
from string import Template
import cherrypy
import time
import subprocess
import SSSDConfig
import logging

SSSD_CONF = '/etc/sssd/sssd.conf'

# LDAP attributes to tell SSSD to fetch over the InfoPipe
SSSD_ATTRS = ['mail',
              'street',
              'locality',
              'postalCode',
              'telephoneNumber',
              'givenname',
              'sn']

# Map the mod_lookup_identity env variables to Ipsilon. The inverse of
# this is in the httpd template.
sssd_mapping = [
    ['REMOTE_USER_GECOS', 'fullname'],
    ['REMOTE_USER_EMAIL', 'email'],
    ['REMOTE_USER_FIRSTNAME', 'givenname'],
    ['REMOTE_USER_LASTNAME', 'surname'],
    ['REMOTE_USER_STREET', 'street'],
    ['REMOTE_USER_STATE', 'state'],
    ['REMOTE_USER_POSTALCODE', 'postcode'],
    ['REMOTE_USER_TELEPHONENUMBER', 'phone'],
]


class InfoProvider(InfoProviderBase):

    def __init__(self, *pargs):
        super(InfoProvider, self).__init__(*pargs)
        self.mapper = Policy(sssd_mapping)
        self.name = 'sssd'
        self.new_config(
            self.name,
            pconfig.Condition(
                'preconfigured',
                'SSSD can only be used when pre-configured',
                False),
        )

    def _get_user_data(self, user):
        reply = dict()
        groups = []
        expectgroups = int(cherrypy.request.wsgi_environ.get(
            'REMOTE_USER_GROUP_N', 0))
        for key in cherrypy.request.wsgi_environ:
            if key.startswith('REMOTE_USER_'):
                if key == 'REMOTE_USER_GROUP_N':
                    continue
                if key.startswith('REMOTE_USER_GROUP_'):
                    groups.append(cherrypy.request.wsgi_environ[key])
                else:
                    reply[key] = cherrypy.request.wsgi_environ[key]
        if len(groups) != expectgroups:
            self.error('Number of groups expected was not found. Expected'
                       ' %d got %d' % (expectgroups, len(groups)))
        return reply, groups

    def get_user_attrs(self, user):
        reply = dict()
        try:
            attrs, groups = self._get_user_data(user)
            userattrs, extras = self.mapper.map_attributes(attrs)
            reply = userattrs
            reply['_groups'] = groups
            reply['_extras'] = {'sssd': extras}

        except KeyError:
            pass

        return reply

    def save_plugin_config(self, *args, **kwargs):
        raise ValueError('Configuration cannot be modified live for SSSD')

    def get_config_obj(self):
        return None

    def enable(self):
        self.refresh_plugin_config()
        if not self.get_config_value('preconfigured'):
            raise Exception("SSSD Can be enabled only if pre-configured")
        super(InfoProvider, self).enable()


CONF_TEMPLATE = """
LoadModule lookup_identity_module modules/mod_lookup_identity.so

<Location /${instance}>
  LookupUserAttr sn REMOTE_USER_LASTNAME
  LookupUserAttr locality REMOTE_USER_STATE
  LookupUserAttr street REMOTE_USER_STREET
  LookupUserAttr telephoneNumber REMOTE_USER_TELEPHONENUMBER
  LookupUserAttr givenname REMOTE_USER_FIRSTNAME
  LookupUserAttr mail REMOTE_USER_EMAIL
  LookupUserAttr postalCode REMOTE_USER_POSTALCODE
  LookupUserGroupsIter REMOTE_USER_GROUP
</Location>
"""


class Installer(InfoProviderInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'sssd'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--info-sssd', choices=['yes', 'no'],
                           default='no',
                           help='Use mod_lookup_identity and SSSD to populate'
                                ' user attrs')
        group.add_argument('--info-sssd-domain', action='append',
                           help='SSSD domain to enable mod_lookup_identity'
                                ' for')

    def configure(self, opts, changes):
        if opts['info_sssd'] != 'yes':
            return

        configured = 0

        confopts = {'instance': opts['instance']}

        tmpl = Template(CONF_TEMPLATE)
        hunk = tmpl.substitute(**confopts)
        with open(opts['httpd_conf'], 'a') as httpd_conf:
            httpd_conf.write(hunk)

        try:
            sssdconfig = SSSDConfig.SSSDConfig()
            sssdconfig.import_config()
        except Exception as e:  # pylint: disable=broad-except
            # Unable to read existing SSSD config so it is probably not
            # configured.
            logging.info('Loading SSSD config failed: %s', e)
            return False

        if not opts['info_sssd_domain']:
            domains = sssdconfig.list_domains()
        else:
            domains = opts['info_sssd_domain']

        changes['domains'] = {}
        for domain in domains:
            changes['domains'][domain] = {}
            try:
                sssd_domain = sssdconfig.get_domain(domain)
            except SSSDConfig.NoDomainError:
                logging.info('No SSSD domain %s', domain)
                continue
            else:
                try:
                    changes['domains'][domain] = {
                        'ldap_user_extra_attrs':
                            sssd_domain.get_option('ldap_user_extra_attrs')}
                except SSSDConfig.NoOptionError:
                    pass
                sssd_domain.set_option(
                    'ldap_user_extra_attrs', ', '.join(SSSD_ATTRS)
                )
                sssdconfig.save_domain(sssd_domain)
                configured += 1
                logging.info("Configured SSSD domain %s", domain)

        if configured == 0:
            logging.info('No SSSD domains configured')
            return False

        changes['ifp'] = {}
        try:
            sssdconfig.new_service('ifp')
            changes['ifp']['new'] = True
        except SSSDConfig.ServiceAlreadyExists:
            changes['ifp']['new'] = False

        sssdconfig.activate_service('ifp')

        ifp = sssdconfig.get_service('ifp')
        if not changes['ifp']['new']:
            try:
                changes['ifp']['allowed_uids'] = ifp.get_option('allowed_uids')
            except SSSDConfig.NoOptionError:
                pass
            try:
                changes['ifp']['user_attributes'] = ifp.get_option(
                    'user_attributes')
            except SSSDConfig.NoOptionError:
                pass
        ifp.set_option('allowed_uids', 'apache, root')
        ifp.set_option('user_attributes', '+' + ', +'.join(SSSD_ATTRS))

        sssdconfig.save_service(ifp)
        sssdconfig.write(SSSD_CONF)

        # for selinux enabled platforms, ignore if it fails just report
        try:
            subprocess.call(['/usr/sbin/setsebool', '-P',
                             'httpd_dbus_sssd=on'])
        except Exception:  # pylint: disable=broad-except
            pass

        try:
            subprocess.call(['/sbin/service', 'sssd', 'restart'])
        except Exception:  # pylint: disable=broad-except
            pass

        # Give SSSD a chance to restart
        time.sleep(5)

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'sssd'
        po.wipe_data()
        po.wipe_config_values()
        config = {'preconfigured': 'True'}
        po.save_plugin_config(config)

        # Update global config to add info plugin
        po.is_enabled = True
        po.save_enabled_state()

    def unconfigure(self, opts, changes):
        try:
            sssdconfig = SSSDConfig.SSSDConfig()
            sssdconfig.import_config()
        except Exception as e:  # pylint: disable=broad-except
            # Unable to read existing SSSD config so it is probably not
            # configured.
            logging.info('Loading SSSD config failed: %s', e)
            return False

        for domain in changes['domains']:
            try:
                sssd_domain = sssdconfig.get_domain(domain.encode('utf-8'))
            except SSSDConfig.NoDomainError:
                logging.info('No SSSD domain %s', domain)
                continue
            else:
                if 'ldap_user_extra_attrs' in changes['domains'][domain]:
                    sssd_domain.set_option('ldap_user_extra_attrs',
                                           changes['domains'][domain][
                                               'ldap_user_extra_attrs'].encode(
                                                   'utf-8'))
                else:
                    sssd_domain.remove_option('ldap_user_extra_attrs')
                sssdconfig.save_domain(sssd_domain)

        if changes['ifp']['new']:
            # We created the service newly, let's remove
            sssdconfig.delete_service('ifp')
        else:
            ifp = sssdconfig.get_service('ifp')
            if 'allowed_uids' in changes['ifp']:
                ifp.set_option('allowed_uids',
                               changes['ifp']['allowed_uids'].encode('utf-8'))
            if 'user_attributes' in changes['ifp']:
                ifp.set_option('user_attributes',
                               changes['ifp']['user_attributes'].encode(
                                   'utf-8'))
            sssdconfig.save_service(ifp)

        sssdconfig.write(SSSD_CONF)

        try:
            subprocess.call(['/sbin/service', 'sssd', 'restart'])
        except Exception:  # pylint: disable=broad-except
            pass

        # Give SSSD a chance to restart
        time.sleep(5)
