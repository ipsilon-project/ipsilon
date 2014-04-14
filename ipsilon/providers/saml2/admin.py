#!/usr/bin/python
#
# Copyright (C) 2014  Simo Sorce <simo@redhat.com>
#
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import cherrypy
from ipsilon.util.page import Page
from ipsilon.providers.saml2.provider import ServiceProvider
from ipsilon.providers.saml2.provider import ServiceProviderCreator
from ipsilon.providers.saml2.provider import InvalidProviderId
import re


VALID_IN_NAME = r'[^\ a-zA-Z0-9]'


class NewSPAdminPage(Page):

    def __init__(self, site, parent):
        super(NewSPAdminPage, self).__init__(site)
        self.parent = parent
        self.title = 'New Service Provider'
        self.backurl = parent.url
        self.url = '%s/new' % (parent.url,)

    def form_new(self, message=None, message_type=None):
        return self._template('admin/providers/saml2_sp_new.html',
                              title=self.title,
                              message=message,
                              message_type=message_type,
                              name='saml2_sp_new_form',
                              backurl=self.backurl, action=self.url)

    def GET(self, *args, **kwargs):
        return self.form_new()

    def POST(self, *args, **kwargs):

        if self.user.is_admin:
            #TODO: allow authenticated user to create SPs on their own
            #      set the owner in that case
            name = None
            meta = None
            if 'content-type' not in cherrypy.request.headers:
                self._debug("Invalid request, missing content-type")
                message = "Malformed request"
                message_type = "error"
                return self.form_new(message, message_type)
            ctype = cherrypy.request.headers['content-type'].split(';')[0]
            if ctype != 'multipart/form-data':
                self._debug("Invalid form type (%s), trying to cope" % (
                            cherrypy.request.content_type,))
            for key, value in kwargs.iteritems():
                if key == 'name':
                    if re.search(VALID_IN_NAME, value):
                        message = "Invalid name!" \
                                  " Use only numbers and letters"
                        message_type = "error"
                        return self.form_new(message, message_type)

                    name = value
                elif key == 'meta':
                    if hasattr(value, 'content_type'):
                        meta = value.fullvalue()
                    else:
                        self._debug("Invalid format for 'meta'")

            if name and meta:
                try:
                    spc = ServiceProviderCreator(self.parent.cfg)
                    sp = spc.create_from_buffer(name, meta)
                    sp_page = self.parent.add_sp(name, sp)
                    message = "SP Successfully added"
                    message_type = "success"
                    return sp_page.form_standard(message, message_type)
                except InvalidProviderId, e:
                    message = str(e)
                    message_type = "error"
                except Exception, e:  # pylint: disable=broad-except
                    self._debug(repr(e))
                    message = "Failed to create Service Provider!"
                    message_type = "error"
            else:
                message = "A name and a metadata file must be provided"
                message_type = "error"
        else:
            message = "Unauthorized"
            message_type = "error"

        return self.form_new(message, message_type)

    def root(self, *args, **kwargs):
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)


class InvalidValueFormat(Exception):
    pass


class UnauthorizedUser(Exception):
    pass


class SPAdminPage(Page):

    def __init__(self, sp, site, parent):
        super(SPAdminPage, self).__init__(site)
        self.parent = parent
        self.sp = sp
        self.title = sp.name
        self.backurl = parent.url
        self.url = '%s/sp/%s' % (parent.url, sp.name)

    def form_standard(self, message=None, message_type=None):
        return self._template('admin/providers/saml2_sp.html',
                              message=message,
                              message_type=message_type,
                              title=self.title,
                              name='saml2_sp_%s_form' % self.sp.name,
                              backurl=self.backurl, action=self.url,
                              data=self.sp)

    def GET(self, *args, **kwargs):
        return self.form_standard()

    def change_name(self, key, value):

        if value == self.sp.name:
            return False

        if self.user.is_admin or self.user.name == self.sp.owner:
            if re.search(VALID_IN_NAME, value):
                err = "Invalid name! Use only numbers and letters"
                raise InvalidValueFormat(err)

            self._debug("Replacing %s: %s -> %s" % (key, self.sp.name, value))
            return {'name': value, 'rename': [self.sp.name, value]}
        else:
            raise UnauthorizedUser("Unauthorized to rename Service Provider")

    def change_owner(self, key, value):
        if value == self.sp.owner:
            return False

        if self.user.is_admin:
            self._debug("Replacing %s: %s -> %s" % (key, self.sp.owner, value))
            return {'owner': value}
        else:
            raise UnauthorizedUser("Unauthorized to set owner value")

    def change_default_nameid(self, key, value):
        if value == self.sp.default_nameid:
            return False

        if self.user.is_admin:
            self._debug("Replacing %s: %s -> %s" % (key,
                                                    self.sp.default_nameid,
                                                    value))
            if not self.sp.is_valid_nameid(value):
                raise InvalidValueFormat('Invalid default nameid value')
            return {'default_nameid': value}
        else:
            raise UnauthorizedUser("Unauthorized to set default nameid value")

    def change_allowed_nameids(self, key, value):
        v = set([x.strip() for x in value.split(',')])
        if v == set(self.sp.allowed_nameids):
            return False

        if self.user.is_admin:
            self._debug("Replacing %s: %s -> %s" % (key,
                                                    self.sp.allowed_nameids,
                                                    list(v)))
            for x in v:
                if not self.sp.is_valid_nameid(x):
                    l = ', '.join(self.sp.valid_nameids())
                    err = 'Invalid nameid [%s]. Available [%s].' % (x, l)
                    raise InvalidValueFormat(err)
            return {'allowed_nameids': list(v)}
        else:
            raise UnauthorizedUser("Unauthorized to set alowed nameids values")

    def POST(self, *args, **kwargs):

        message = "Nothing was modified."
        message_type = "info"
        results = dict()

        try:
            for key, value in kwargs.iteritems():
                if key == 'name':
                    r = self.change_name(key, value)
                    if r:
                        results.update(r)
                elif key == 'owner':
                    r = self.change_owner(key, value)
                    if r:
                        results.update(r)

                elif key == 'default_nameid':
                    r = self.change_default_nameid(key, value)
                    if r:
                        results.update(r)

                elif key == 'allowed_nameids':
                    r = self.change_allowed_nameids(key, value)
                    if r:
                        results.update(r)

        except InvalidValueFormat, e:
            message = str(e)
            message_type = "warning"
            return self.form_standard(message, message_type)
        except UnauthorizedUser, e:
            message = str(e)
            message_type = "error"
            return self.form_standard(message, message_type)
        except Exception, e:  # pylint: disable=broad-except
            self._debug("Error: %s" % repr(e))
            message = "Internal Error"
            message_type = "error"
            return self.form_standard(message, message_type)

        if len(results) > 0:
            try:
                if 'name' in results:
                    self.sp.name = results['name']
                if 'owner' in results:
                    self.sp.owner = results['owner']
                if 'default_nameid' in results:
                    self.sp.default_nameid = results['default_nameid']
                if 'allowed_nameids' in results:
                    self.sp.allowed_nameids = results['allowed_nameids']
                self.sp.save_properties()
                if 'rename' in results:
                    rename = results['rename']
                    self.parent.rename_sp(rename[0], rename[1])
                message = "Properties succssfully changed"
                message_type = "success"
            except Exception:  # pylint: disable=broad-except
                message = "Failed to save data!"
                message_type = "error"

        return self.form_standard(message, message_type)

    def root(self, *args, **kwargs):
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)

    def delete(self):
        self.parent.del_sp(self.sp.name)
        self.sp.permanently_delete()
        return self.parent.root()
    delete.exposed = True


class AdminPage(Page):
    def __init__(self, site, config):
        super(AdminPage, self).__init__(site)
        self.name = 'admin'
        self.cfg = config
        self.providers = []
        self.menu = []
        self.url = None
        self.sp = Page(self._site)

    def add_sp(self, name, sp):
        page = SPAdminPage(sp, self._site, self)
        self.sp.add_subtree(name, page)
        self.providers.append(sp)
        return page

    def rename_sp(self, oldname, newname):
        page = getattr(self.sp, oldname)
        self.sp.del_subtree(oldname)
        self.sp.add_subtree(newname, page)

    def del_sp(self, name):
        try:
            page = getattr(self.sp, name)
            self.providers.remove(page.sp)
            self.sp.del_subtree(name)
        except Exception, e:  # pylint: disable=broad-except
            self._debug("Failed to remove provider %s: %s" % (name, str(e)))

    def mount(self, page):
        self.menu = page.menu
        self.url = '%s/%s' % (page.url, self.name)
        for p in self.cfg.idp.get_providers():
            try:
                sp = ServiceProvider(self.cfg, p)
                self.add_sp(sp.name, sp)
            except Exception, e:  # pylint: disable=broad-except
                self._debug("Failed to find provider %s: %s" % (p, str(e)))
        self.add_subtree('new', NewSPAdminPage(self._site, self))
        page.add_subtree(self.name, self)

    def root(self, *args, **kwargs):
        return self._template('admin/providers/saml2.html',
                              title='SAML2 Administration',
                              providers=self.providers,
                              baseurl=self.url,
                              menu=self.menu)
