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


class InvalidProviderId(Exception):

    def __init__(self, message):
        msg = 'Invalid Provider ID: %s' % message
        super(InvalidProviderId, self).__init__(msg)
        self.message = msg

    def __str__(self):
        return repr(self.message)


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

    @property
    def provider_id(self):
        return self._properties['id']

    @property
    def name(self):
        return self._properties['name']

    @property
    def allowed_namedids(self):
        if 'allowed nameid' in self._properties:
            return self._properties['allowed nameid']
        else:
            return self.cfg.default_allowed_nameids

    @property
    def default_nameid(self):
        if 'default nameid' in self._properties:
            return self._properties['default nameid']
        else:
            return self.cfg.default_nameid

    def get_valid_nameid(self, nip):
        self._debug('Requested NameId [%s]' % (nip.format,))
        if nip.format == None:
            return NAMEID_MAP[self.default_nameid]
        elif nip.format == lasso.SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED:
            return NAMEID_MAP[self.default_nameid]
        else:
            allowed = self.allowed_namedids
            self._debug('Allowed NameIds %s' % (repr(allowed)))
            for nameid in allowed:
                if nip.format == NAMEID_MAP[nameid]:
                    return nip.format
        raise NameIdNotAllowed()

    def _debug(self, fact):
        if cherrypy.config.get('debug', False):
            cherrypy.log(fact)
