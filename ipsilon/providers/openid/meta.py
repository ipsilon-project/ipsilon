# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.providers.common import ProviderPageBase

import cherrypy


class MetaHandler(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(MetaHandler, self).__init__(*args, **kwargs)
        self._template_name = None
        self._take_args = False

    def reply(self, **kwargs):
        if self._template_name is None:
            raise ValueError('Template not set')
        return str(self._template(self._template_name, **kwargs))

    def default(self, *args, **kwargs):
        if self._take_args:
            return self.root(*args, **kwargs)
        raise cherrypy.NotFound()


class XRDSHandler(MetaHandler):

    def __init__(self, *args, **kwargs):
        super(XRDSHandler, self).__init__(*args, **kwargs)
        self.default_headers['Content-Type'] = 'application/xrds+xml'
        self._template_name = 'openid/xrds.xml'

    def GET(self, *args, **kwargs):
        types = [
            'http://specs.openid.net/auth/2.0/server',
            'http://openid.net/server/1.0',
        ]
        for _, e in self.cfg.extensions.available().items():
            types.extend(e.get_type_uris())

        return self.reply(types=types,
                          uri=self.cfg.endpoint_url)


class UserXRDSHandler(XRDSHandler):

    def __init__(self, *args, **kwargs):
        super(UserXRDSHandler, self).__init__(*args, **kwargs)
        self._take_args = True

    def GET(self, *args, **kwargs):
        if len(args) != 1:
            raise cherrypy.NotFound()
        if args[0].endswith('.xrds'):
            name = args[0][:-5]
            identity_url = self.cfg.identity_url_template % {'username': name}
            types = [
                'http://specs.openid.net/auth/2.0/signon',
                'http://openid.net/signon/1.0',
            ]
            for _, e in self.cfg.extensions.available().items():
                types.extend(e.get_type_uris())

            return self.reply(types=types,
                              uri=self.cfg.endpoint_url,
                              localid=identity_url)

        raise cherrypy.NotFound()


class IDHandler(MetaHandler):

    def __init__(self, *args, **kwargs):
        super(IDHandler, self).__init__(*args, **kwargs)
        self._template_name = 'openid/userpage.html'
        self._take_args = True

    def GET(self, *args, **kwargs):
        if len(args) != 1:
            raise cherrypy.NotFound()
        name = args[0]
        yadis = '%syadis/%s.xrds' % (self.cfg.endpoint_url, name)
        cherrypy.response.headers['X-XRDS-Location'] = yadis

        endpoint_url = self.cfg.endpoint_url
        identity_url = self.cfg.identity_url_template % {'username': name}

        HEAD_LINK = '<link rel="%s" href="%s">'
        provider_heads = [HEAD_LINK % ('openid2.provider', endpoint_url),
                          HEAD_LINK % ('openid.server', endpoint_url)]
        user_heads = [HEAD_LINK % ('openid2.delegate', identity_url),
                      HEAD_LINK % ('openid.local_id', identity_url)]
        heads = {'provider': provider_heads, 'user': user_heads}

        return self.reply(title='Userpage', username=name, heads=heads)
