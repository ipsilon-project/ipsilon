# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

import cherrypy
import cStringIO
import inspect
import os
import traceback
import logging


def log_request_response():
    '''Log the contents of the request and subsequent response.

    This is run as a tool hook and should be run as the last hook
    (on_end_resource) just before the server writes the response to
    the client. The tool is registered like this:

    cherrypy.tools.log_request_response = \
        cherrypy.Tool('on_end_resource', log_request_response)

    Then the logging can be enabled or disabled via the config option,
    for example to turn the logging on via a config dict add this
    key/value pair:

    'tools.log_request_response.on': True,

    or for a config file add this line:

    tools.log_request_response.on = True

    At first blush it would seem easy to log the request received and
    the response emitted, just hook those locations and output the raw
    data. Unfortunately there are no such locations in cherrypy where
    you have access to the raw input and output data. The complicating
    factors are:

    * Input data is consumed by the Request object off a file object
      which cannot seek back (i.e. rewind), once the data is read it
      cannot be read again. Therefore any attempt to log the raw input
      will starve read operations done by the Request object to read
      the headers and body.

    * Automatic consumption and processing of the body contents is
      enabled by default (controlled by the
      request.process_request_body config option). You generally do
      not want to turn these automatic request processors off because
      they provide valuable input processing useful to the request
      processing pipeline (e.g. when Content-Type is
      application/x-www-form-urlencoded, or multipart/form-data or
      multipart). Most cherrypy page handlers expect this
      pre-processing to have been performed and the 'cooked' data to
      be availabe on the Request object. Thus rather than logging the
      raw input HTTP which will have been consumed by the request
      processing logic we are forced into logging only the 'cooked'
      values available to us after the request has been read and
      processed.

    * The response body may not be available if response streaming is
      enabled. This is because control is passed directly to the
      object writing the data to the client bypassing the normal
      cherrypy hooks. Fortunately streaming is not recommended and we
      can expect it will be disabled. When streaming is disabled the
      response body can be composed as:

        - string
        - list of strings
        - a generator yielding chunks of strings

      When the response body is a string or list of strings logging
      the body and then passing down the pipeline to be written to the
      client is trivial. However when part of the body is produced by
      a generator we must run the generator to produce that part of
      the body and store it as a string. This is an issue equivalent
      to not being able to re-read a file object as seen in the input
      situation. Once the generator has run it cannot be run
      again. Therefore we consume all the body output, store it in a
      string, log it and then replace the request body contents with
      the body string we formed. It's this body string which is
      subsequently sent down the processing pipeline to be written to
      the client.

    '''

    # --- Begin local functions ---

    def indent_text(text, level=0, indent='    '):
        '''
        Input is a block of text potentially containing newlines which
        seperate the text into a sequence of lines. The text block is
        split into individual lines and indented according to the
        indentation level. The width of the indent is controlled by
        the optional indent parameter.

        The result is a single block of text where each of the
        original lines of text are indented.
        '''

        f = cStringIO.StringIO()

        lines = text.split('\n')

        # Do not output trailing newline
        if lines and lines[-1] == '':
            lines.pop(-1)

        for line in lines:
            f.write(indent*level)
            f.write(line)
            f.write('\n')

        string = f.getvalue()
        f.close()
        return string

    def print_part(part):
        '''
        Format a cherrypy._cpreqbody.Part object into a string.

        When the request Content-Type is a multipart cherrypy splits
        each part of the multipart into a Part object containing
        information about the part and it's content.
        '''
        f = cStringIO.StringIO()

        f.write(indent_text('Name = %s\n' % part.name))
        if part.headers:
            f.write(indent_text('Headers:\n'))
            for name, value in part.headers.items():
                f.write(indent_text('%s: %s\n' % (name, value), 1))

        f.write(indent_text("Body:\n"))
        f.write(indent_text(part.fullvalue(), 1))

        string = f.getvalue()
        f.close()
        return string

    def print_param(name, value):
        f = cStringIO.StringIO()

        # Might be a multipart Part object, if so format it
        if isinstance(value, cherrypy._cpreqbody.Part):  # pylint:disable=W0212
            f.write(indent_text("%s:\n" % (name)))
            f.write(indent_text(print_part(value), 1))
        else:
            # Not a mulitpart, just write it as a string
            f.write(indent_text("%s: %s\n" % (name, value)))

        string = f.getvalue()
        f.close()
        return string

    def collapse_body(body):
        '''The cherrypy response body can be:

        * string
        * list of strings
        * generator yielding a string

        Generators are typically used for file contents but any
        cherrypy response is permitted to use a generator to provide
        the body of the response.

        Strings and lists of strings are immediately available and
        stored in the request object. During normal cherrypy
        processing when writing the response to the client response
        data which is provided by a generator will be iterated over
        and written to the client. In order for us to be able to log
        all the response data prior to it being sent to the client we
        must also iterate over the generator provided content, however
        this exhausts the generator making it unavailable to be
        written to the client.

        To solve this problem we collect all the response data. Now we
        have the full body contents, we can log it and then set this
        as the new body contents for remainder of the processing
        pipeline to act upon (i.e. sent to the client)
        '''
        f = cStringIO.StringIO()

        for chunk in body:
            f.write(chunk)

        string = f.getvalue()
        f.close()
        return string

    # --- End local functions ---

    f = cStringIO.StringIO()
    request = cherrypy.serving.request
    remote = request.remote

    #
    # Log the Request
    #
    f.write(indent_text("<Request> [%s] %s\n" %
                        (remote.name or remote.ip, request.request_line), 0))

    # Request Headers
    if request.headers:
        f.write(indent_text("Headers:\n", 1))
        for name, value in request.headers.items():
            f.write(indent_text("%s: %s\n" % (name, value), 2))

    # Request parameters from URL query string and
    # x-www-form-urlencoded POST data
    if request.body.params:
        f.write(indent_text("Params:\n", 1))
        for name, value in request.body.params.items():
            # Multi-valued paramater is in a list
            if isinstance(value, list):
                for i, item in enumerate(value):
                    f.write(indent_text(print_param("%s[%d]" % (name, i),
                                                    item), 2))
            else:
                f.write(indent_text(print_param(name, value), 2))

    # If the body is multipart format each of the parts
    if request.body.parts:
        f.write(indent_text("Body Parts:\n"))
        for i, part in enumerate(request.body.parts):
            f.write(indent_text("Part %s name=%s:\n" % (i, part.name), 3))
            f.write(indent_text(print_part(part), 4))

    #
    # Log the Response
    #
    response = cherrypy.response
    f.write(indent_text("<Response> %s\n" % response.status, 0))

    # Log the response headers
    if response.header_list:
        f.write(indent_text("Headers:\n", 1))
        for name, value in response.header_list:
            f.write(indent_text("%s: %s\n" % (name, value), 2))

    # Log the response body
    #
    # We can only do this if the response is not streaming because we have
    # no way to hook the streaming content.
    f.write(indent_text("Body:\n", 1))

    if response.stream:
        f.write(indent_text("body omitted because response is streaming\n", 2))
    else:
        response.body = collapse_body(response.body)
        for chunk in response.body:
            f.write(indent_text(chunk, 2))

    string = f.getvalue()
    f.close()
    print string

cherrypy.tools.log_request_response = cherrypy.Tool('on_end_resource',
                                                    log_request_response)


class Log(object):

    @staticmethod
    def stacktrace():
        buf = cStringIO.StringIO()

        stack = traceback.extract_stack()
        traceback.print_list(stack[:-2], file=buf)

        stacktrace_string = buf.getvalue()
        buf.close()
        return stacktrace_string

    @staticmethod
    def get_class_from_frame(frame_obj):
        '''
        Taken from:
        http://stackoverflow.com/questions/2203424/
        python-how-to-retrieve-class-information-from-a-frame-object

        At the frame object level, there does not seem to be any way
        to find the actual python function object that has been
        called.

        However, if your code relies on the common convention of naming
        the instance parameter of a method self, then you could do this.
        '''

        args, _, _, value_dict = inspect.getargvalues(frame_obj)
        # Is the functions first parameter named 'self'?
        if len(args) and args[0] == 'self':
            # in that case, 'self' will be referenced in value_dict
            instance = value_dict.get('self', None)
            if instance:
                # return its class
                return getattr(instance, '__class__', None)
        # return None otherwise
        return None

    @staticmethod
    def call_location():
        frame = inspect.stack()[2]
        frame_obj = frame[0]
        filename = frame[1]
        line_number = frame[2]
        func = frame[3]

        # Only report the last 3 components of the path
        filename = os.sep.join(filename.split(os.sep)[-3:])

        cls = Log.get_class_from_frame(frame_obj)
        if cls:
            location = '%s:%s %s.%s()' %  \
                       (filename, line_number, cls.__name__, func)
        else:
            location = '%s:%s %s()' % (filename, line_number, func)
        return location

    def debug(self, fact):
        if cherrypy.config.get('debug', False):
            location = Log.call_location()
            cherrypy.log('DEBUG(%s): %s' % (location, fact))

    # for compatibility with existing code
    _debug = debug

    def log(self, fact):
        cherrypy.log(fact)

    def error(self, fact):
        cherrypy.log.error('ERROR: %s' % fact, severity=logging.ERROR)
        if cherrypy.config.get('stacktrace_on_error', False):
            cherrypy.log.error(Log.stacktrace())
