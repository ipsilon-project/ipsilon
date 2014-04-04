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

from ipsilon.providers.common import ProviderException
import cherrypy
import lasso


NAMEID_MAP = {
    'email': lasso.SAML2_NAME_IDENTIFIER_FORMAT_EMAIL,
    'encrypted': lasso.SAML2_NAME_IDENTIFIER_FORMAT_ENCRYPTED,
    'entity': lasso.SAML2_NAME_IDENTIFIER_FORMAT_ENTITY,
    'kerberos': lasso.SAML2_NAME_IDENTIFIER_FORMAT_KERBEROS,
    'persistent': lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT,
    'transient': lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT,
    'unspecified': lasso.SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED,
    'windows': lasso.SAML2_NAME_IDENTIFIER_FORMAT_WINDOWS,
    'x509': lasso.SAML2_NAME_IDENTIFIER_FORMAT_X509,
}


class InvalidProviderId(ProviderException):

    def __init__(self, code):
        message = 'Invalid Provider ID: %s' % code
        super(InvalidProviderId, self).__init__(message)
        self._debug(message)


class NameIdNotAllowed(Exception):

    def __init__(self):
        message = 'The specified Name ID is not allowed'
        super(NameIdNotAllowed, self).__init__(message)
        self.message = message

    def __str__(self):
        return repr(self.message)


class ServiceProvider(object):

    def __init__(self, config, provider_id):
        self.cfg = config
        data = self.cfg.get_data(name='id', value=provider_id)
        if len(data) != 1:
            raise InvalidProviderId('multiple matches')
        idval = data.keys()[0]
        data = self.cfg.get_data(idval=idval)
        self._properties = data[idval]
        self._staging = dict()

    @property
    def provider_id(self):
        return self._properties['id']

    @property
    def name(self):
        return self._properties['name']

    @name.setter
    def name(self, value):
        self._staging['name'] = value

    @property
    def owner(self):
        if 'owner' in self._properties:
            return self._properties['owner']
        else:
            return ''

    @owner.setter
    def owner(self, value):
        self._staging['owner'] = value

    @property
    def allowed_nameids(self):
        if 'allowed nameids' in self._properties:
            allowed = self._properties['allowed nameids']
            return [x.strip() for x in allowed.split(',')]
        else:
            return self.cfg.default_allowed_nameids

    @allowed_nameids.setter
    def allowed_nameids(self, value):
        if type(value) is not list:
            raise ValueError("Must be a list")
        self._staging['allowed nameids'] = ','.join(value)

    @property
    def default_nameid(self):
        if 'default nameid' in self._properties:
            return self._properties['default nameid']
        else:
            return self.cfg.default_nameid

    @default_nameid.setter
    def default_nameid(self, value):
        self._staging['default nameid'] = value

    def save_properties(self):
        data = self.cfg.get_data(name='id', value=self.provider_id)
        if len(data) != 1:
            raise InvalidProviderId('Could not find SP data')
        idval = data.keys()[0]
        data = dict()
        data[idval] = self._staging
        self.cfg.save_data(data)
        data = self.cfg.get_data(idval=idval)
        self._properties = data[idval]
        self._staging = dict()

    def get_valid_nameid(self, nip):
        self._debug('Requested NameId [%s]' % (nip.format,))
        if nip.format is None:
            return NAMEID_MAP[self.default_nameid]
        elif nip.format == lasso.SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED:
            return NAMEID_MAP[self.default_nameid]
        else:
            allowed = self.allowed_nameids
            self._debug('Allowed NameIds %s' % (repr(allowed)))
            for nameid in allowed:
                if nip.format == NAMEID_MAP[nameid]:
                    return nip.format
        raise NameIdNotAllowed(nip.format)

    def permanently_delete(self):
        data = self.cfg.get_data(name='id', value=self.provider_id)
        if len(data) != 1:
            raise InvalidProviderId('Could not find SP data')
        idval = data.keys()[0]
        self.cfg.del_datum(idval)

    def _debug(self, fact):
        if cherrypy.config.get('debug', False):
            cherrypy.log(fact)

    def normalize_username(self, username):
        if 'strip domain' in self._properties:
            return username.split('@', 1)[0]
        return username


class ServiceProviderCreator(object):

    def __init__(self, config):
        self.cfg = config

    def create_from_buffer(self, name, metabuf):
        '''Test and add data'''

        test = lasso.Server()
        test.addProviderFromBuffer(lasso.PROVIDER_ROLE_SP, metabuf)
        newsps = test.get_providers()
        if len(newsps) != 1:
            raise InvalidProviderId("Metadata must contain one Provider")

        spid = newsps.keys()[0]
        data = self.cfg.get_data(name='id', value=spid)
        if len(data) != 0:
            raise InvalidProviderId("Provider Already Exists")
        datum = {'id': spid, 'name': name, 'type': 'SP', 'metadata': metabuf}
        self.cfg.new_datum(datum)

        data = self.cfg.get_data(name='id', value=spid)
        if len(data) != 1:
            raise InvalidProviderId("Internal Error")
        idval = data.keys()[0]
        data = self.cfg.get_data(idval=idval)
        sp = data[idval]
        self.cfg.idp.add_provider(sp)

        return ServiceProvider(self.cfg, spid)


class IdentityProvider(object):
    def __init__(self, config):
        self.server = lasso.Server(config.idp_metadata_file,
                                   config.idp_key_file,
                                   None,
                                   config.idp_certificate_file)
        self.server.role = lasso.PROVIDER_ROLE_IDP

    def add_provider(self, sp):
        self.server.addProviderFromBuffer(lasso.PROVIDER_ROLE_SP,
                                          sp['metadata'])
        self._debug('Added SP %s' % sp['name'])

    def get_login_handler(self, dump=None):
        if dump:
            return lasso.Login.newFromDump(self.server, dump)
        else:
            return lasso.Login(self.server)

    def get_providers(self):
        return self.server.get_providers()

    def _debug(self, fact):
        if cherrypy.config.get('debug', False):
            cherrypy.log(fact)
