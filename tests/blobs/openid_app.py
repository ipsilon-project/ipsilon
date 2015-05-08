# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

import sys
sys.stdout = sys.stderr

import cherrypy
import os
import pwd

from openid.consumer import consumer
from openid.extensions import sreg, ax
from openid_teams import teams


class OpenIDApp(object):
    def index(self, extensions):
        self.extensions = extensions == 'YES'
        oidconsumer = consumer.Consumer(dict(), None)
        try:
            request = oidconsumer.begin('http://127.0.0.10:45080/idp1/')
        except Exception as ex:
            return 'ERROR: %s' % ex

        if request is None:
            return 'ERROR: No request'

        # Attach extensions here
        if self.extensions:
            request.addExtension(sreg.SRegRequest(
                required=['nickname', 'email', 'timezone']))
            ax_req = ax.FetchRequest()
            ax_req_name = ax.AttrInfo('http://schema.openid.net/namePerson')
            ax_req.add(ax_req_name)
            request.addExtension(ax_req)
            username = pwd.getpwuid(os.getuid())[0]
            request.addExtension(teams.TeamsRequest(requested=[username]))

        # Build and send final request
        trust_root = cherrypy.url()
        return_to = trust_root + 'finish'
        if request.shouldSendRedirect():
            redirect_url = request.redirectURL(
                trust_root, return_to)
            raise cherrypy.HTTPRedirect(redirect_url)
        else:
            return request.htmlMarkup(
                trust_root, return_to)
    index.exposed = True

    def finish(self, **args):
        oidconsumer = consumer.Consumer(dict(), None)
        info = oidconsumer.complete(cherrypy.request.params, cherrypy.url())
        display_identifier = info.getDisplayIdentifier()

        if info.status == consumer.FAILURE and display_identifier:
            return 'ERROR:Verification of %s failed: %s' % (
                display_identifier, info.message)
        elif info.status == consumer.CANCEL:
            return 'ERROR: Cancelled'
        elif info.status == consumer.SUCCESS:
            username = pwd.getpwuid(os.getuid())[0]
            expected_identifier = 'http://127.0.0.10:45080/idp1/openid/id/%s/'\
                % username
            if expected_identifier != display_identifier:
                return 'ERROR: Wrong id returned: %s != %s' % (
                    expected_identifier,
                    display_identifier)

            if self.extensions:
                sreg_resp = sreg.SRegResponse.fromSuccessResponse(info)
                teams_resp = teams.TeamsResponse.fromSuccessResponse(info)
                ax_resp = ax.FetchResponse.fromSuccessResponse(info)

                if sreg_resp is None:
                    return 'ERROR: No sreg!'
                elif teams_resp is None:
                    return 'ERROR: No teams!'
                elif ax_resp is None:
                    return 'ERROR: No AX!'

                # Check values
                expected_name = 'Test User %s' % username
                expected_email = '%s@example.com' % username

                ax_name = ax_resp.data[
                    'http://schema.openid.net/namePerson'][0]
                sreg_email = sreg_resp.data['email']

                if ax_name != expected_name:
                    return 'ERROR: Wrong name returned: %s != %s' % (
                        expected_name,
                        ax_name)

                if sreg_email != expected_email:
                    return 'ERROR: Wrong email returned: %s != %s' % (
                        expected_email,
                        sreg_email)

                if username not in teams_resp.teams:
                    return 'ERROR: User not in self-named group (%s not in %s)' %\
                        (username, teams_resp.teams)

            if self.extensions:
                return 'SUCCESS, WITH EXTENSIONS'
            else:
                return 'SUCCESS, WITHOUT EXTENSIONS'
        else:
            return 'ERROR: Strange error: %s' % info.message
    finish.exposed = True


cherrypy.config['environment'] = 'embedded'

application = cherrypy.Application(OpenIDApp(),
                                   script_name=None, config=None)
