# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.providers.common import ProviderBase, ProviderPageBase, \
    ProviderInstaller
from ipsilon.providers.saml2.auth import AuthenticateRequest
from ipsilon.providers.saml2.logout import LogoutRequest
from ipsilon.providers.saml2.admin import Saml2AdminPage
from ipsilon.providers.saml2.rest import Saml2RestBase
from ipsilon.providers.saml2.provider import IdentityProvider
from ipsilon.providers.saml2.sessions import SAMLSessionFactory
from ipsilon.util.data import SAML2SessionStore
from ipsilon.tools.certs import Certificate
from ipsilon.tools import saml2metadata as metadata
from ipsilon.tools import files
from ipsilon.util.http import require_content_type
from ipsilon.util.constants import SOAP_MEDIA_TYPE, XML_MEDIA_TYPE
from ipsilon.util.user import UserSession
from ipsilon.util.plugin import PluginObject
from ipsilon.util import config as pconfig
import cherrypy
from datetime import timedelta
import lasso
import os
import time
import uuid

cherrypy.tools.require_content_type = cherrypy.Tool('before_request_body',
                                                    require_content_type)


def is_lasso_ecp_enabled():
    # Full ECP support appeared in lasso version 2.4.2
    return lasso.checkVersion(2, 4, 2, lasso.CHECK_VERSION_NUMERIC)


class SSO_SOAP(AuthenticateRequest):

    def __init__(self, *args, **kwargs):
        super(SSO_SOAP, self).__init__(*args, **kwargs)
        self.binding = metadata.SAML2_SERVICE_MAP['sso-soap'][1]

    @cherrypy.tools.require_content_type(
        required=[SOAP_MEDIA_TYPE, XML_MEDIA_TYPE])
    @cherrypy.tools.accept(media=[SOAP_MEDIA_TYPE, XML_MEDIA_TYPE])
    @cherrypy.tools.response_headers(
        headers=[('Content-Type', 'SOAP_MEDIA_TYPE')])
    def POST(self, *args, **kwargs):
        self.debug("SSO_SOAP.POST() begin")

        self.debug("SSO_SOAP transaction provider=%s id=%s" %
                   (self.trans.provider, self.trans.transaction_id))

        us = UserSession()
        us.remote_login()
        user = us.get_user()
        self.debug("SSO_SOAP user=%s" % (user.name))

        if not user:
            raise cherrypy.HTTPError(403, 'No user specified for SSO_SOAP')

        soap_xml_doc = cherrypy.request.rfile.read()
        soap_xml_doc = soap_xml_doc.strip()
        self.debug("SSO_SOAP soap_xml_doc=%s" % soap_xml_doc)
        login = self.saml2login(soap_xml_doc)

        return self.auth(login)


class Redirect(AuthenticateRequest):

    def __init__(self, *args, **kwargs):
        super(Redirect, self).__init__(*args, **kwargs)
        self.binding = metadata.SAML2_SERVICE_MAP['sso-redirect'][1]

    def GET(self, *args, **kwargs):

        query = cherrypy.request.query_string

        login = self.saml2login(query)
        return self.auth(login)


class POSTAuth(AuthenticateRequest):

    def __init__(self, *args, **kwargs):
        super(POSTAuth, self).__init__(*args, **kwargs)
        self.binding = metadata.SAML2_SERVICE_MAP['sso-post'][1]

    def POST(self, *args, **kwargs):

        request = kwargs.get(lasso.SAML2_FIELD_REQUEST)
        relaystate = kwargs.get(lasso.SAML2_FIELD_RELAYSTATE)

        login = self.saml2login(request)
        login.set_msgRelayState(relaystate)
        return self.auth(login)


class Continue(AuthenticateRequest):

    def GET(self, *args, **kwargs):

        session = UserSession()
        user = session.get_user()
        transdata = self.trans.retrieve()
        self.stage = transdata['saml2_stage']

        if user.is_anonymous:
            self.debug("User is marked anonymous?!")
            # TODO: Return to SP with auth failed error
            raise cherrypy.HTTPError(401)

        self.debug('Continue auth for %s' % user.name)

        if 'saml2_request' not in transdata:
            self.debug("Couldn't find Request dump?!")
            # TODO: Return to SP with auth failed error
            raise cherrypy.HTTPError(400)
        dump = transdata['saml2_request']

        try:
            login = self.cfg.idp.get_login_handler(dump)
        except Exception, e:  # pylint: disable=broad-except
            self.debug('Failed to load status from dump: %r' % e)

        if not login:
            self.debug("Empty Request dump?!")
            # TODO: Return to SP with auth failed error
            raise cherrypy.HTTPError(400)

        return self.auth(login)


class RedirectLogout(LogoutRequest):

    def GET(self, *args, **kwargs):
        query = cherrypy.request.query_string

        relaystate = kwargs.get(lasso.SAML2_FIELD_RELAYSTATE)
        response = kwargs.get(lasso.SAML2_FIELD_RESPONSE)

        return self.logout(query,
                           relaystate=relaystate,
                           samlresponse=response)


class SSO(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(SSO, self).__init__(*args, **kwargs)
        self.Redirect = Redirect(*args, **kwargs)
        self.POST = POSTAuth(*args, **kwargs)
        self.Continue = Continue(*args, **kwargs)
        self.SOAP = SSO_SOAP(*args, **kwargs)


class SLO(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(SLO, self).__init__(*args, **kwargs)
        self.debug('SLO init')
        self.Redirect = RedirectLogout(*args, **kwargs)


# one week
METADATA_RENEW_INTERVAL = 60 * 60 * 24 * 7
# five years (approximately)
METADATA_DEFAULT_VALIDITY_PERIOD = 365 * 5


class Metadata(ProviderPageBase):
    def GET(self, *args, **kwargs):

        body = self._get_metadata()
        cherrypy.response.headers["Content-Type"] = XML_MEDIA_TYPE
        cherrypy.response.headers["Content-Disposition"] = \
            'attachment; filename="metadata.xml"'
        return body

    def _get_metadata(self):
        if os.path.isfile(self.cfg.idp_metadata_file):
            s = os.stat(self.cfg.idp_metadata_file)
            if s.st_mtime > time.time() - METADATA_RENEW_INTERVAL:
                with open(self.cfg.idp_metadata_file) as m:
                    return m.read()

        # Otherwise generate and save
        idp_cert = Certificate()
        idp_cert.import_cert(self.cfg.idp_certificate_file,
                             self.cfg.idp_key_file)

        validity = int(self.cfg.idp_metadata_validity)
        meta = IdpMetadataGenerator(self.instance_base_url(), idp_cert,
                                    timedelta(validity))
        body = meta.output()
        with open(self.cfg.idp_metadata_file, 'w+') as m:
            m.write(body)
        return body


class SAML2(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(SAML2, self).__init__(*args, **kwargs)
        self.metadata = Metadata(*args, **kwargs)
        self.SSO = SSO(*args, **kwargs)
        self.SLO = SLO(*args, **kwargs)


class IdpProvider(ProviderBase):

    def __init__(self, *pargs):
        super(IdpProvider, self).__init__('saml2', 'saml2', *pargs)
        self.admin = None
        self.rest = None
        self.page = None
        self.idp = None
        self.sessionfactory = None
        self.description = """
Provides SAML 2.0 authentication infrastructure. """

        self.new_config(
            self.name,
            pconfig.String(
                'idp storage path',
                'Path to data storage accessible by the IdP.',
                '/var/lib/ipsilon/saml2'),
            pconfig.String(
                'idp metadata file',
                'The IdP Metadata file generated at install time.',
                'metadata.xml'),
            pconfig.String(
                'idp metadata validity',
                'The IdP Metadata validity period (in days) to use when '
                'generating new metadata.',
                METADATA_DEFAULT_VALIDITY_PERIOD),
            pconfig.String(
                'idp certificate file',
                'The IdP PEM Certificate generated at install time.',
                'certificate.pem'),
            pconfig.String(
                'idp key file',
                'The IdP Certificate Key generated at install time.',
                'certificate.key'),
            pconfig.String(
                'idp nameid salt',
                'The salt used for persistent Name IDs.',
                None),
            pconfig.Condition(
                'allow self registration',
                'Allow authenticated users to register applications.',
                True),
            pconfig.Choice(
                'default allowed nameids',
                'Default Allowed NameIDs for Service Providers.',
                metadata.SAML2_NAMEID_MAP.keys(),
                ['unspecified', 'persistent', 'transient', 'email',
                 'kerberos', 'x509']),
            pconfig.Pick(
                'default nameid',
                'Default NameID used by Service Providers.',
                metadata.SAML2_NAMEID_MAP.keys(),
                'unspecified'),
            pconfig.String(
                'default email domain',
                'Used for users missing the email property.',
                'example.com'),
            pconfig.MappingList(
                'default attribute mapping',
                'Defines how to map attributes before returning them to SPs',
                [['*', '*']]),
            pconfig.ComplexList(
                'default allowed attributes',
                'Defines a list of allowed attributes, applied after mapping',
                ['*']),
            pconfig.String(
                'session database url',
                'Database URL for SAML2 sessions',
                'saml2.sessions.db.sqlite'),
        )
        if cherrypy.config.get('debug', False):
            import logging
            import sys
            logger = logging.getLogger('lasso')
            lh = logging.StreamHandler(sys.stderr)
            logger.addHandler(lh)
            logger.setLevel(logging.DEBUG)

        store = SAML2SessionStore(
            database_url=self.get_config_value('session database url')
        )
        bt = cherrypy.process.plugins.BackgroundTask(
            60, store.remove_expired_sessions
        )
        bt.start()

    @property
    def allow_self_registration(self):
        return self.get_config_value('allow self registration')

    @property
    def idp_storage_path(self):
        return self.get_config_value('idp storage path')

    @property
    def idp_metadata_file(self):
        return os.path.join(self.idp_storage_path,
                            self.get_config_value('idp metadata file'))

    @property
    def idp_metadata_validity(self):
        return self.get_config_value('idp metadata validity')

    @property
    def idp_certificate_file(self):
        return os.path.join(self.idp_storage_path,
                            self.get_config_value('idp certificate file'))

    @property
    def idp_key_file(self):
        return os.path.join(self.idp_storage_path,
                            self.get_config_value('idp key file'))

    @property
    def idp_nameid_salt(self):
        return self.get_config_value('idp nameid salt')

    @property
    def default_allowed_nameids(self):
        return self.get_config_value('default allowed nameids')

    @property
    def default_nameid(self):
        return self.get_config_value('default nameid')

    @property
    def default_email_domain(self):
        return self.get_config_value('default email domain')

    @property
    def default_attribute_mapping(self):
        return self.get_config_value('default attribute mapping')

    @property
    def default_allowed_attributes(self):
        return self.get_config_value('default allowed attributes')

    def get_tree(self, site):
        self.idp = self.init_idp()
        self.page = SAML2(site, self)
        self.admin = Saml2AdminPage(site, self)
        self.rest = Saml2RestBase(site, self)
        return self.page

    def init_idp(self):
        idp = None
        self.sessionfactory = SAMLSessionFactory(
            database_url=self.get_config_value('session database url')
        )
        # Init IDP data
        try:
            idp = IdentityProvider(self,
                                   sessionfactory=self.sessionfactory)
        except Exception, e:  # pylint: disable=broad-except
            self.debug('Failed to init SAML2 provider: %r' % e)
            return None

        self._root.logout.add_handler(self.name, self.idp_initiated_logout)

        # Import all known applications
        data = self.get_data()
        for idval in data:
            sp = data[idval]
            if 'type' not in sp or sp['type'] != 'SP':
                continue
            if 'name' not in sp or 'metadata' not in sp:
                continue
            try:
                idp.add_provider(sp)
            except Exception, e:  # pylint: disable=broad-except
                self.debug('Failed to add SP %s: %r' % (sp['name'], e))

        return idp

    def on_enable(self):
        super(IdpProvider, self).on_enable()
        self.idp = self.init_idp()
        if hasattr(self, 'admin'):
            if self.admin:
                self.admin.add_sps()

    def idp_initiated_logout(self):
        """
        Logout all SP sessions when the logout comes from the IdP.

        For the current user only.
        """
        self.debug("IdP-initiated SAML2 logout")
        us = UserSession()
        user = us.get_user()

        saml_sessions = self.sessionfactory
        session = saml_sessions.get_next_logout()
        if session is None:
            return

        logout = self.idp.get_logout_handler()
        logout.setSessionFromDump(session.login_session)
        logout.initRequest(session.provider_id)
        try:
            logout.buildRequestMsg()
        except lasso.Error, e:
            self.error('failure to build logout request msg: %s' % e)
            raise cherrypy.HTTPRedirect(400, 'Failed to log out user: %s '
                                        % e)

        # Add a fake session to indicate where the user should
        # be redirected to when all SP's are logged out.
        idpurl = self._root.instance_base_url()
        session_id = "_" + uuid.uuid4().hex.upper()
        saml_sessions.add_session(session_id, idpurl, user.name, "")
        init_session = saml_sessions.get_session_by_id(session_id)
        saml_sessions.start_logout(init_session, relaystate=idpurl)

        # Add the logout request id we just created to the session to be
        # logged out so that when it responds we can find the right
        # session.
        session.set_logoutstate(request_id=logout.request.id)
        saml_sessions.start_logout(session, initial=False)

        self.debug('Sending initial logout request to %s' % logout.msgUrl)
        raise cherrypy.HTTPRedirect(logout.msgUrl)


class IdpMetadataGenerator(object):

    def __init__(self, url, idp_cert, expiration=None):
        self.meta = metadata.Metadata(metadata.IDP_ROLE, expiration)
        self.meta.set_entity_id('%s/saml2/metadata' % url)
        self.meta.add_certs(idp_cert, idp_cert)
        self.meta.add_service(metadata.SAML2_SERVICE_MAP['sso-post'],
                              '%s/saml2/SSO/POST' % url)
        self.meta.add_service(metadata.SAML2_SERVICE_MAP['sso-redirect'],
                              '%s/saml2/SSO/Redirect' % url)
        if is_lasso_ecp_enabled():
            self.meta.add_service(metadata.SAML2_SERVICE_MAP['sso-soap'],
                                  '%s/saml2/SSO/SOAP' % url)
        self.meta.add_service(metadata.SAML2_SERVICE_MAP['logout-redirect'],
                              '%s/saml2/SLO/Redirect' % url)
        self.meta.add_allowed_name_format(
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT)
        self.meta.add_allowed_name_format(
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT)
        self.meta.add_allowed_name_format(
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_EMAIL)

    def output(self, path=None):
        return self.meta.output(path)


class Installer(ProviderInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'saml2'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--saml2', choices=['yes', 'no'], default='yes',
                           help='Configure SAML2 Provider')
        group.add_argument('--saml2-metadata-validity',
                           default=METADATA_DEFAULT_VALIDITY_PERIOD,
                           help=('Metadata validity period in days '
                                 '(default - %d)' %
                                 METADATA_DEFAULT_VALIDITY_PERIOD))
        group.add_argument('--saml2-session-dburl',
                           help='session database URL')

    def configure(self, opts, changes):
        if opts['saml2'] != 'yes':
            return

        # Check storage path is present or create it
        path = os.path.join(opts['data_dir'], 'saml2')
        if not os.path.exists(path):
            os.makedirs(path, 0700)

        # Use the same cert for signing and ecnryption for now
        cert = Certificate(path)
        cert.generate('idp', opts['hostname'])

        # Generate Idp Metadata
        proto = 'https'
        if opts['secure'].lower() == 'no':
            proto = 'http'
        url = '%s://%s/%s' % (proto, opts['hostname'], opts['instance'])
        validity = int(opts['saml2_metadata_validity'])
        meta = IdpMetadataGenerator(url, cert,
                                    timedelta(validity))
        if 'gssapi' in opts and opts['gssapi'] == 'yes':
            meta.meta.add_allowed_name_format(
                lasso.SAML2_NAME_IDENTIFIER_FORMAT_KERBEROS)

        meta.output(os.path.join(path, 'metadata.xml'))

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'saml2'
        po.wipe_data()
        po.wipe_config_values()
        config = {'idp storage path': path,
                  'idp metadata file': 'metadata.xml',
                  'idp certificate file': cert.cert,
                  'idp key file': cert.key,
                  'idp nameid salt': uuid.uuid4().hex,
                  'idp metadata validity': opts['saml2_metadata_validity'],
                  'session database url': opts['saml2_session_dburl'] or
                  opts['database_url'] % {
                      'datadir': opts['data_dir'],
                      'dbname': 'saml2.sessions.db'}}
        po.save_plugin_config(config)

        # Update global config to add login plugin
        po.is_enabled = True
        po.save_enabled_state()

        # Fixup permissions so only the ipsilon user can read these files
        files.fix_user_dirs(path, opts['system_user'])
