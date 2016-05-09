# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from __future__ import absolute_import

from ipsilon.providers.openidc.plugins.common import OpenidCExtensionBase


class OpenidCExtension(OpenidCExtensionBase):

    def __init__(self, provider, *pargs):
        name = 'ipsilon'
        display_name = 'Ipsilon Token API'
        scopes = {
            'ipsilon_token': 'Ipsilon token verification'
        }

        super(OpenidCExtension, self).__init__(provider,
                                               name,
                                               display_name,
                                               scopes)
