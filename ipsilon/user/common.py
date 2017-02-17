# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.page import Page
from ipsilon.util.user import UserSession
import cherrypy


class UserPortalPage(Page):
    def __init__(self, *args, **kwargs):
        super(UserPortalPage, self).__init__(*args, **kwargs)
        self.auth_protect = True


class UserPortalConsent(UserPortalPage):
    def __init__(self, site, parent, mount):
        super(UserPortalConsent, self).__init__(site)
        self._master = parent
        self.title = 'User portal consent'
        self.url = '%s/%s' % (parent.url, 'consent')
        self.menu = [self]

    def revoke(self, provider, clientid):
        us = UserSession()
        user = us.get_user()

        provname = provider
        provmod = self._site['provider_config'].available.get(provname,
                                                              None)
        if provmod is not None:
            if not provmod.revoke_consent(user.name, clientid):
                raise Exception('Provider refused to revoke')
        user.revoke_consent(provider, clientid)
        raise cherrypy.HTTPRedirect(self._master.url)
    revoke.public_function = True


class UserPortal(UserPortalPage):
    def __init__(self, site, mount):
        super(UserPortal, self).__init__(site)
        self.title = 'User portal'
        self.url = '%s/%s' % (self.basepath, mount)
        self.menu = [self]
        self.consent = UserPortalConsent(site, self, 'consent')

    def root(self, *args, **kwargs):
        us = UserSession()
        user = us.get_user()
        consents = user.list_consents()

        for consent in consents:
            provname = consent['provider']
            provider = self._site['provider_config'].available.get(provname,
                                                                   None)

            if provider is not None:
                consent['providerdn'] = provider.get_display_name()
                consent['clientdn'] = provider.\
                    get_client_display_name(consent['client'])
                attrs = provider.consent_to_display(consent['attrs'])
            else:
                self.debug('Consent relates to unknown provider %s' % provname)
                attrs = []
            consent['attrs'] = attrs

        return self._template('user/index.html',
                              title='',
                              baseurl=self.url,
                              menu=self.menu,
                              consents=consents)
