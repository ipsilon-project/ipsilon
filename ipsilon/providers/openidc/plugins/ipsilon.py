# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from __future__ import absolute_import

from ipsilon.providers.openidc.plugins.common import OpenidCExtensionBase


class OpenidCExtension(OpenidCExtensionBase):
    name = 'ipsilon'
    display_name = 'Ipsilon Token API'
    scopes = {
        'ipsilon_token': {
            'display_name': 'Ipsilon token verification'
        }
    }
