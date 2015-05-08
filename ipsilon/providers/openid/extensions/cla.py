# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from __future__ import absolute_import

from ipsilon.providers.openid.extensions.common import OpenidExtensionBase
from openid_cla import cla


class OpenidExtension(OpenidExtensionBase):

    def __init__(self, *pargs):
        super(OpenidExtension, self).__init__('CLAs')
        self.type_uris = [
            cla.cla_uri,
        ]

    def _resp(self, request, userdata):
        req = cla.CLARequest.fromOpenIDRequest(request)
        self.debug(req)
        if req is None:
            return {}
        data = userdata.get('_extras', {}).get('cla', [])
        return cla.CLAResponse.extractResponse(req, data)

    def _display(self, request, userdata):
        resp = self._resp(request, userdata)
        if resp.clas:
            return {'CLA': 'yes'}
        return {}

    def _response(self, request, userdata):
        return self._resp(request, userdata)
