# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

import cherrypy
from ipsilon.util.page import Page
from ipsilon.util.log import Log
from ipsilon.util.endpoint import allow_iframe

import json


class WebFinger(Page, Log):

    def __init__(self, site):
        super(WebFinger, self).__init__(site)
        self.supported_rels = {}

    @allow_iframe
    def root(self, *args, **kwargs):
        cherrypy.response.headers.update({
            'Content-Type': 'application/jrd+json',
            'Access-Control-Allow-Origin': '*'
        })

        if 'resource' not in kwargs:
            raise cherrypy.HTTPError(400, 'Missing resource parameter')

        resource = kwargs['resource']
        self.debug('WebFinger request for %s' % resource)

        response = {'subject': resource,
                    'links': [],
                    'properties': {}}
        found = False

        if 'rel' in kwargs:
            rels = kwargs['rel']
            if isinstance(rels, basestring):
                rels = [rels]
        else:
            rels = self.supported_rels.keys()

        for rel in rels:
            if rel in self.supported_rels:
                func = self.supported_rels[rel]
                rel_resp = func(resource)
                self.debug('Rel %s returned %s' % (rel, rel_resp))
                if 'links' in rel_resp:
                    if len(rel_resp['links']) > 0:
                        found = True
                        response['links'].extend(rel_resp['links'])
                if 'properties' in rel_resp:
                    if len(rel_resp['properties']) > 0:
                        found = True
                        response['properties'].update(rel_resp['properties'])

        if not found:
            # None of the plugins had any info, we don't know this resource
            raise cherrypy.HTTPError(404, 'No info about resource found')

        response['subject'] = resource

        return json.dumps(response)

    def register_rel(self, rel, function):
        if rel in self.supported_rels:
            raise KeyError('Rel %s already registered' % rel)

        self.debug('WebFinger rel %s registered as %s'
                   % (rel, function))
        self.supported_rels[rel] = function

    def unregister_rel(self, rel):
        if rel not in self.supported_rels:
            raise KeyError('Rel %s not registered' % rel)

        self.debug('WebFinger rel %s unregistered' % rel)
        del self.supported_rels[rel]
