# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.page import Page


class Errors(Page):

    def __init__(self, *args, **kwargs):
        super(Errors, self).__init__(*args, **kwargs)

    def _error_template(self, *args, **kwargs):
        output_page = self._template(*args, **kwargs)
        # for some reason cherrypy will choke if the output
        # is a unicode object, so use str() here to please it
        return str(output_page)

    def handler(self, status, message, traceback, version):
        self.debug(repr([status, message, traceback, version]))
        return self._error_template('internalerror.html',
                                    title='Internal Error')

    # pylint: disable=W0221
    def __call__(self, status, message, traceback, version):
        return self.handler(status, message, traceback, version)


class Error_400(Errors):

    def handler(self, status, message, traceback, version):
        return self._error_template('badrequest.html',
                                    title='Bad Request', message=message)


class Error_401(Errors):

    def handler(self, status, message, traceback, version):
        return self._error_template('unauthorized.html',
                                    title='Unauthorized', message=message)


class Error_404(Errors):

    def handler(self, status, message, traceback, version):
        return self._error_template('notfound.html',
                                    title='Not Found', message=message)
