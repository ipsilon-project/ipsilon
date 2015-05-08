# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from __future__ import absolute_import

from ipsilon.providers.openid.extensions.teams import Teams
from openid_teams import teams


class OpenidExtension(Teams):

    def __init__(self, *pargs):
        super(OpenidExtension, self).__init__('Fedora Teams')

    def _resp(self, request, userdata):
        req = teams.TeamsRequest.fromOpenIDRequest(request)
        if req is None:
            return {}
        if '_FAS_ALL_GROUPS_' in req.requested:
            # We will send all groups the user is a member of
            req.requested = userdata.get('_groups', [])
        data = userdata.get('_groups', [])
        return teams.TeamsResponse.extractResponse(req, data)
