# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from __future__ import absolute_import

from ipsilon.providers.openid.extensions.common import OpenidExtensionBase
from openid_teams import teams


class Teams(OpenidExtensionBase):

    def __init__(self, name):
        super(Teams, self).__init__(name)
        self.type_uris = [
            teams.teams_uri,
        ]

    def _resp(self, request, userdata):
        req = teams.TeamsRequest.fromOpenIDRequest(request)
        if req is None:
            return {}
        data = userdata.get('_groups', [])
        return teams.TeamsResponse.extractResponse(req, data)

    def _display(self, request, userdata):
        resp = self._resp(request, userdata)
        if resp.teams:
            return {'Groups': resp.teams}
        return {}

    def _response(self, request, userdata):
        return self._resp(request, userdata)


class OpenidExtension(Teams):
    def __init__(self, *pargs):
        super(OpenidExtension, self).__init__('Teams')
