# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

from ipsilon.rest.common import RestPlugins
from ipsilon.providers.common import FACILITY


class RestProviderPlugins(RestPlugins):
    def __init__(self, site, parent):
        super(RestProviderPlugins, self).__init__('providers', site, parent,
                                                  FACILITY, ordered=False)
        self.title = 'Identity Providers'
