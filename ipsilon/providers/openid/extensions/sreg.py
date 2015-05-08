# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from __future__ import absolute_import

from ipsilon.providers.openid.extensions.common import OpenidExtensionBase
from openid.extensions import sreg


class OpenidExtension(OpenidExtensionBase):

    def __init__(self, *pargs):
        super(OpenidExtension, self).__init__('Simple Registration')
        self.type_uris = [
            sreg.ns_uri_1_1,
            sreg.ns_uri_1_0,
        ]

    def _resp(self, request, userdata):
        req = sreg.SRegRequest.fromOpenIDRequest(request)
        data = dict()
        for name in sreg.data_fields:
            if name in userdata:
                data[name] = userdata[name]
        return sreg.SRegResponse.extractResponse(req, data)

    def _display(self, request, userdata):
        resp = self._resp(request, userdata)
        return resp.data

    def _response(self, request, userdata):
        return self._resp(request, userdata)
