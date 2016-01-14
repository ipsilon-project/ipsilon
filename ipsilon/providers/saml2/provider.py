# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.providers.common import ProviderException
from ipsilon.util import config as pconfig
from ipsilon.util.config import ConfigHelper
from ipsilon.tools.saml2metadata import SAML2_NAMEID_MAP, NSMAP
from ipsilon.util.log import Log
from lxml import etree
import lasso
import re


VALID_IN_NAME = r'[^\ a-zA-Z0-9]'


class InvalidProviderId(ProviderException):

    def __init__(self, msg):
        message = 'Invalid Provider ID: %s' % msg
        super(InvalidProviderId, self).__init__(message)
        self.debug(message)


class InvalidProviderMetadata(ProviderException):

    def __init__(self, msg):
        message = 'Invalid Provider Metadata: %s' % msg
        super(InvalidProviderMetadata, self).__init__(message)
        self.debug(message)


class NameIdNotAllowed(Exception):

    def __init__(self, nid):
        message = 'Name ID [%s] is not allowed' % nid
        super(NameIdNotAllowed, self).__init__(message)
        self.message = message

    def __str__(self):
        return repr(self.message)


def validate_sp_metadata(metadata):
    '''Validate SP metadata

    Attempt to load the metadata into Lasso and verify it loads.
    Assure only 1 provider is included in the metadata and return
    it's id. If not valid raise an exception.

    Note, loading the metadata into Lasso is a weak check, basically
    all that Lasso does is to parse the XML, it doesn't verify the
    contents until first use.
    '''
    test = lasso.Server()
    try:
        test.addProviderFromBuffer(lasso.PROVIDER_ROLE_SP, metadata)
    except Exception as e:  # pylint: disable=broad-except
        raise InvalidProviderMetadata(str(e))
    newsps = test.get_providers()
    if len(newsps) != 1:
        raise InvalidProviderMetadata("Metadata must contain one Provider")

    spid = newsps.keys()[0]
    return spid


class ServiceProviderConfig(ConfigHelper):
    def __init__(self):
        super(ServiceProviderConfig, self).__init__()


class ServiceProvider(ServiceProviderConfig):

    def __init__(self, config, provider_id):
        super(ServiceProvider, self).__init__()
        self.cfg = config
        data = self.cfg.get_data(name='id', value=provider_id)
        if len(data) != 1:
            raise InvalidProviderId('multiple matches')
        idval = data.keys()[0]
        data = self.cfg.get_data(idval=idval)
        self._properties = data[idval]
        self._staging = dict()
        self.load_config()
        self.logout_mechs = []
        xmldoc = etree.XML(str(data[idval]['metadata']))
        logout = xmldoc.xpath('//md:EntityDescriptor'
                              '/md:SPSSODescriptor'
                              '/md:SingleLogoutService',
                              namespaces=NSMAP)
        for service in logout:
            self.logout_mechs.append(service.values()[0])
        self.has_signing_keys = len(xmldoc.xpath('//md:EntityDescriptor'
                                                 '/md:SPSSODescriptor'
                                                 '/md:KeyDescriptor'
                                                 '[@use="signing"]',
                                                 namespaces=NSMAP)) > 0

    def load_config(self):
        self.new_config(
            self.provider_id,
            pconfig.String(
                'Name',
                'A nickname used to easily identify the Service Provider.'
                ' Only alphanumeric characters [A-Z,a-z,0-9] and spaces are'
                '  accepted.',
                self.name),
            pconfig.String(
                'Metadata',
                "Service Provider's metadata",
                self.metadata,
                multiline=True),
            pconfig.String(
                'Description',
                'A description of the SP to show on the Portal.',
                self.description),
            pconfig.String(
                'Service Provider link',
                'A link to the Service Provider for the Portal.',
                self.splink),
            pconfig.Condition(
                'Visible in Portal',
                'This SP is visible in the Portal.',
                self.visible),
            pconfig.Image(
                'Image File',
                'Image to display for this SP in the Portal. Scale to '
                '100x200 for best results.',
                self.imagefile),
            pconfig.Pick(
                'Default NameID',
                'Default NameID used by Service Providers.',
                SAML2_NAMEID_MAP.keys(),
                self.default_nameid),
            pconfig.Choice(
                'Allowed NameIDs',
                'Allowed NameIDs for this Service Provider.',
                SAML2_NAMEID_MAP.keys(),
                self.allowed_nameids),
            pconfig.String(
                'User Owner',
                'The user that owns this Service Provider',
                self.owner),
            pconfig.MappingList(
                'Attribute Mapping',
                'Defines how to map attributes before returning them to'
                ' the SP. Setting this overrides the global values.',
                self.attribute_mappings),
            pconfig.ComplexList(
                'Allowed Attributes',
                'Defines a list of allowed attributes, applied after mapping.'
                ' Setting this overrides the global values.',
                self.allowed_attributes),
        )

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
    def metadata(self):
        if 'metadata' in self._properties:
            return self._properties['metadata']
        else:
            return ''

    @metadata.setter
    def metadata(self, value):
        self._staging['metadata'] = value

    @property
    def description(self):
        return self._properties.get('description', '')

    @description.setter
    def description(self, value):
        self._staging['description'] = value

    @property
    def visible(self):
        return self._properties.get('visible', True)

    @visible.setter
    def visible(self, value):
        self._staging['visible'] = value

    @property
    def imagefile(self):
        return self._properties.get('imagefile', '')

    @imagefile.setter
    def imagefile(self, value):
        self._staging['imagefile'] = value

    @property
    def imageurl(self):
        return pconfig.url_from_image(self._properties['imagefile'])

    @property
    def splink(self):
        return self._properties.get('splink', '')

    @splink.setter
    def splink(self, value):
        self._staging['splink'] = value

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
        if not isinstance(value, list):
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

    @property
    def attribute_mappings(self):
        if 'attribute mappings' in self._properties:
            attr_map = pconfig.MappingList('temp', 'temp', None)
            attr_map.import_value(str(self._properties['attribute mappings']))
            return attr_map.get_value()
        else:
            return None

    @attribute_mappings.setter
    def attribute_mappings(self, attr_map):
        if isinstance(attr_map, pconfig.MappingList):
            value = attr_map.export_value()
        else:
            temp = pconfig.MappingList('temp', 'temp', None)
            temp.set_value(attr_map)
            value = temp.export_value()
        self._staging['attribute mappings'] = value

    @property
    def allowed_attributes(self):
        if 'allowed_attributes' in self._properties:
            attr_map = pconfig.ComplexList('temp', 'temp', None)
            attr_map.import_value(str(self._properties['allowed_attributes']))
            return attr_map.get_value()
        else:
            return None

    @allowed_attributes.setter
    def allowed_attributes(self, attr_map):
        if isinstance(attr_map, pconfig.ComplexList):
            value = attr_map.export_value()
        else:
            temp = pconfig.ComplexList('temp', 'temp', None)
            temp.set_value(attr_map)
            value = temp.export_value()
        self._staging['allowed_attributes'] = value

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

    def refresh_config(self):
        """
        Create a new config object for displaying in the UI based on
        the current set of properties.
        """
        del self._config
        self.load_config()

    def get_valid_nameid(self, nip):
        if nip is None or nip.format is None:
            self.debug('No NameId requested, returning default [%s]'
                       % SAML2_NAMEID_MAP[self.default_nameid])
            return SAML2_NAMEID_MAP[self.default_nameid]
        else:
            self.debug('Requested NameId [%s]' % (nip.format,))
            allowed = self.allowed_nameids
            self.debug('Allowed NameIds %s' % (repr(allowed)))
            for nameid in allowed:
                if nip.format == SAML2_NAMEID_MAP[nameid]:
                    return nip.format
        raise NameIdNotAllowed(nip.format)

    def get_signature_hint(self):
        """
        Call this before any lasso process message methods to get
        the hint on whether to enforce signatures or not.
        """
        if self.has_signing_keys:
            hint = lasso.PROFILE_SIGNATURE_VERIFY_HINT_FORCE
        else:
            hint = lasso.PROFILE_SIGNATURE_VERIFY_HINT_IGNORE

        self.error(
            'Setting signature hint to "%s"' %
            (hint == lasso.PROFILE_SIGNATURE_VERIFY_HINT_FORCE and
             "force" or "ignore")
        )

        return hint

    def permanently_delete(self):
        data = self.cfg.get_data(name='id', value=self.provider_id)
        if len(data) != 1:
            raise InvalidProviderId('Could not find SP data')
        idval = data.keys()[0]
        self.cfg.del_datum(idval)

    def normalize_username(self, username):
        if 'strip domain' in self._properties:
            return username.split('@', 1)[0]
        return username

    def is_valid_name(self, value):
        if re.search(VALID_IN_NAME, value):
            return False
        return True

    def is_valid_nameid(self, value):
        if value in SAML2_NAMEID_MAP:
            return True
        return False

    def valid_nameids(self):
        return SAML2_NAMEID_MAP.keys()


class ServiceProviderCreator(object):

    def __init__(self, config):
        self.cfg = config

    def create_from_buffer(self, name, metabuf, description='',
                           visible=True, imagefile='', splink=''):
        '''Test and add data'''

        if re.search(VALID_IN_NAME, name):
            raise InvalidProviderId("Name must contain only "
                                    "numbers and letters")

        spid = validate_sp_metadata(metabuf)
        data = self.cfg.get_data(name='id', value=spid)
        if len(data) != 0:
            raise InvalidProviderId("Provider Already Exists")
        datum = {
            'id': spid,
            'name': name,
            'type': 'SP',
            'metadata': metabuf,
            'description': description,
            'visible': visible,
            'imagefile': imagefile,
            'splink': splink,
        }
        self.cfg.new_datum(datum)

        data = self.cfg.get_data(name='id', value=spid)
        if len(data) != 1:
            raise InvalidProviderId("Internal Error")
        idval = data.keys()[0]
        data = self.cfg.get_data(idval=idval)
        sp = data[idval]
        self.cfg.idp.add_provider(sp)

        return ServiceProvider(self.cfg, spid)


class IdentityProvider(Log):
    def __init__(self, config, sessionfactory):
        self.server = lasso.Server(config.idp_metadata_file,
                                   config.idp_key_file,
                                   None,
                                   config.idp_certificate_file)
        self.server.role = lasso.PROVIDER_ROLE_IDP
        self.sessionfactory = sessionfactory

    def add_provider(self, sp):
        validate_sp_metadata(sp['metadata'])
        self.server.addProviderFromBuffer(lasso.PROVIDER_ROLE_SP,
                                          sp['metadata'])
        self.debug('Added SP %s' % sp['name'])

    def get_login_handler(self, dump=None):
        if dump:
            return lasso.Login.newFromDump(self.server, dump)
        else:
            return lasso.Login(self.server)

    def get_providers(self):
        return self.server.get_providers()

    def get_logout_handler(self, dump=None):
        if dump:
            return lasso.Logout.newFromDump(self.server, dump)
        else:
            return lasso.Logout(self.server)
