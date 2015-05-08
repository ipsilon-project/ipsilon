# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from __future__ import absolute_import

from ipsilon.providers.openid.extensions.common import OpenidExtensionBase
from openid.extensions import ax


AP_MAP = {
    'http://schema.openid.net/namePerson': 'fullname',
    'http://schema.openid.net/contact/email': 'email',
    'http://axschema.org/namePerson': 'fullname',
    'http://axschema.org/namePerson/first': 'firstname',
    'http://axschema.org/namePerson/last': 'lastname',
    'http://axschema.org/namePerson/friendly': 'nickname',
    'http://axschema.org/contact/email': 'email',
    'http://openid.net/schema/namePerson/first': 'firstname',
    'http://openid.net/schema/namePerson/last': 'lastname',
    'http://openid.net/schema/namePerson/friendly': 'nickname',
    'http://openid.net/schema/gender': 'gender',
    'http://openid.net/schema/language/pref': 'language',
    'http://fedoauth.org/openid/schema/GPG/keyid': 'gpg_keyid',
    'http://fedoauth.org/openid/schema/SSH/key': 'ssh_key',
}


class OpenidExtension(OpenidExtensionBase):

    def __init__(self, *pargs):
        super(OpenidExtension, self).__init__('Attribute Exchange')
        self.type_uris = [
            ax.AXMessage.ns_uri,
        ]

    def _resp(self, request, userdata):
        req = ax.FetchRequest.fromOpenIDRequest(request)
        if req is None:
            return None
        resp = ax.FetchResponse(req)
        for name in req.requested_attributes:
            try:
                self.debug(name)
                if name in AP_MAP:
                    resp.addValue(name, userdata[AP_MAP[name]])
                else:
                    resp.addValue(name, userdata[name])
            except Exception:  # pylint: disable=broad-except
                pass
        return resp

    def _display(self, request, userdata):
        resp = self._resp(request, userdata)
        if resp is None:
            return {}
        data = dict()
        for name, value in resp.data.items():
            key = name
            if name in AP_MAP:
                key = AP_MAP[name]
            data[key] = ', '.join(value if value else [])
        return data

    def _response(self, request, userdata):
        return self._resp(request, userdata)
