# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.admin.common import AdminPlugins
from ipsilon.providers.common import FACILITY


class ProviderPlugins(AdminPlugins):
    def __init__(self, site, parent):
        super(ProviderPlugins, self).__init__('providers', site, parent,
                                              FACILITY, ordered=False)
        self.title = 'Identity Providers'
        self.template = 'admin/providers.html'
