# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

import cherrypy
from ipsilon.providers.common import RestProviderBase
from ipsilon.providers.common import FACILITY
from ipsilon.rest.common import rest_error, jsonout
from ipsilon.providers.saml2.provider import ServiceProviderCreator
from ipsilon.providers.saml2.provider import InvalidProviderId
from ipsilon.util.page import admin_protect
from lasso import ServerAddProviderFailedError


class Saml2RestBase(RestProviderBase):
    """
    The root for REST pages.

    Add new REST classes to this via add_subtree().
    """

    def __init__(self, site, config):
        super(Saml2RestBase, self).__init__(site, config)
        self.name = 'saml2'
        self.cfg = config
        self.url = None

    def mount(self, page):
        self.url = page.url
        self.add_subtree('SPS', SPS(self._site, self))
        page.add_subtree(self.name, self)


class SPS(RestProviderBase):
    """
    REST interface for Service Providers
    """

    def __init__(self, site, parent):
        super(SPS, self).__init__(site, parent)

        self.parent = parent
        self.backurl = parent.url
        self.url = '%s/SPS' % (parent.url,)

    def __get_idp(self):
        """
        Return the identity provider object
        """
        return self._site[FACILITY].available[self.parent.plugin_name]

    def _get_sp(self, *args, **kwargs):
        """
        If PATH_INFO contains a value then get that value as the name of
        the SP, otherwise return a list of all available SPs.
        """
        if len(args) > 0:
            instance = args[0]
        else:
            instance = None

        idp = self.__get_idp()

        results = list()

        if instance is not None:
            data = idp.get_data(name='name', value=instance)
            if len(data) == 0:
                return rest_error(404, 'Provider %s not found' % instance)
            idval = data.keys()[0]
            data = idp.get_data(idval=idval)
        else:
            data = idp.get_data()

        for idval in data.keys():
            result = dict(provider=data[idval].get('name'),
                          metadata=data[idval].get('metadata'),)
            results.append(result)

        return dict(result=results)

    @jsonout
    @admin_protect
    def GET(self, *args, **kwargs):
        return self._get_sp(*args, **kwargs)

    @jsonout
    @admin_protect
    def POST(self, *args, **kwargs):
        cherrypy.response.status = 201

        if len(args) != 1:
            return rest_error(400, 'Invalid arguments. Found %d'
                                   ' there should be one.')
        name = args[0]
        metadata = kwargs.get('metadata')

        obj = self._site[FACILITY].available[self.parent.plugin_name]
        try:
            spc = ServiceProviderCreator(obj)
            sp = spc.create_from_buffer(name, metadata)
        except (InvalidProviderId, ServerAddProviderFailedError) as e:
            self.debug(repr(e))
            return rest_error(400, str(e))
        except Exception, e:  # pylint: disable=broad-except
            self.debug(repr(e))
            return rest_error(500, "Failed to create Service Provider")

        obj.admin.add_sp(name, sp)

        # Added. Now fetch and return the SP data
        return self._get_sp(name)
