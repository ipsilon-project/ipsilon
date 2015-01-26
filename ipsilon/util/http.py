# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

import cherrypy
import fnmatch


def require_content_type(required=None, absent_ok=True, debug=False):
    '''CherryPy Tool that validates request Content-Type.

    This is a CherryPy Tool that checks the Content-Type in a request and
    raises HTTP Error 415 "Unsupported Media Type" if it does not match.

    The tool accepts a glob style pattern or list of patterns (see fnmatch)
    and verifies the Content-Type in the request matches at least one of
    the patterns, if not a HTTP Error 415 "Unsupported Media Type" is raised.

    If absent_ok is False and if the request does not contain a
    Content-Type header a HTTP Error 415 "Unsupported Media Type" is
    raised.

    The tool may be deployed use any of the standard methods for
    invoking CherryPy tools, for example as a decorator:

    @cherrypy.tools.require_content_type(required='text/xml')
    def POST(self, *args, **kwargs):
        pass

    :param required: May be a single string or a list of strings. Each
           string is interpreted as a glob style pattern (see fnmatch).
           The Content-Type must match at least one pattern.

    :param absent_ok: Boolean specifying if the Content-Type header
           must be present or if it is OK to be absent.

    '''
    if required is None:
        return

    if isinstance(required, basestring):
        required = [required]

    content_type = cherrypy.request.body.content_type.value
    pattern = None
    match = False
    if content_type:
        for pattern in required:
            if fnmatch.fnmatch(content_type, pattern):
                match = True
                break
    else:
        if absent_ok:
            return

    if debug:
        cherrypy.log('require_content_type: required=%s, absent_ok=%s '
                     'content_type=%s match=%s pattern=%s' %
                     required, absent_ok, content_type, match, pattern)

    if not match:
        acceptable = ', '.join(['"%s"' % x for x in required])
        if content_type:
            content_type = '"%s"' % content_type
        else:
            content_type = 'not specified'
        message = ('Content-Type must match one of following patterns [%s], '
                   'but the Content-Type was %s' %
                   (acceptable, content_type))
        raise cherrypy.HTTPError(415, message=message)
