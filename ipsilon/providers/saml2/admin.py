# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

import cherrypy
from ipsilon.util import config as pconfig
from ipsilon.admin.common import AdminPage
from ipsilon.admin.common import ADMIN_STATUS_OK
from ipsilon.admin.common import ADMIN_STATUS_ERROR
from ipsilon.admin.common import ADMIN_STATUS_WARN
from ipsilon.admin.common import get_mapping_list_value
from ipsilon.admin.common import get_complex_list_value
from ipsilon.providers.saml2.provider import ServiceProvider
from ipsilon.providers.saml2.provider import ServiceProviderCreator
from ipsilon.providers.saml2.provider import InvalidProviderId
from copy import deepcopy
import requests
import logging


class NewSPAdminPage(AdminPage):

    def __init__(self, site, parent):
        super(NewSPAdminPage, self).__init__(site, form=True)
        self.parent = parent
        self.title = 'New Service Provider'
        self.back = parent.url
        self.url = '%s/new' % (parent.url,)

    def form_new(self, message=None, message_type=None):
        return self._template('admin/providers/saml2_sp_new.html',
                              title=self.title,
                              message=message,
                              message_type=message_type,
                              name='saml2_sp_new_form',
                              back=self.back, action=self.url)

    def GET(self, *args, **kwargs):
        return self.form_new()

    def POST(self, *args, **kwargs):

        if self.user.is_admin:
            # TODO: allow authenticated user to create SPs on their own
            #       set the owner in that case
            name = None
            meta = None
            if 'content-type' not in cherrypy.request.headers:
                self.debug("Invalid request, missing content-type")
                message = "Malformed request"
                message_type = ADMIN_STATUS_ERROR
                return self.form_new(message, message_type)
            ctype = cherrypy.request.headers['content-type'].split(';')[0]
            if ctype != 'multipart/form-data':
                self.debug("Invalid form type (%s), trying to cope" % (
                           cherrypy.request.content_type,))
            for key, value in kwargs.iteritems():
                if key == 'name':
                    name = value
                elif key == 'metatext':
                    if len(value) > 0:
                        meta = value
                elif key == 'metafile':
                    if hasattr(value, 'content_type'):
                        meta = value.fullvalue()
                    else:
                        self.debug("Invalid format for 'meta'")
                elif key == 'metaurl':
                    if len(value) > 0:
                        try:
                            r = requests.get(value)
                            r.raise_for_status()
                            meta = r.content
                        except Exception, e:  # pylint: disable=broad-except
                            self.debug("Failed to fetch metadata: " + repr(e))
                            message = "Failed to fetch metadata: " + repr(e)
                            message_type = ADMIN_STATUS_ERROR
                            return self.form_new(message, message_type)

            if name and meta:
                try:
                    spc = ServiceProviderCreator(self.parent.cfg)
                    sp = spc.create_from_buffer(name, meta)
                    sp_page = self.parent.add_sp(name, sp)
                    message = "SP Successfully added"
                    message_type = ADMIN_STATUS_OK
                    return sp_page.root_with_msg(message, message_type)
                except InvalidProviderId, e:
                    message = str(e)
                    message_type = ADMIN_STATUS_ERROR
                except Exception, e:  # pylint: disable=broad-except
                    self.debug(repr(e))
                    message = "Failed to create Service Provider!"
                    message_type = ADMIN_STATUS_ERROR
            else:
                message = "A name and a metadata file must be provided"
                message_type = ADMIN_STATUS_ERROR
        else:
            message = "Unauthorized"
            message_type = ADMIN_STATUS_ERROR

        return self.form_new(message, message_type)


class InvalidValueFormat(Exception):
    pass


class UnauthorizedUser(Exception):
    pass


class SPAdminPage(AdminPage):

    def __init__(self, sp, site, parent):
        super(SPAdminPage, self).__init__(site, form=True)
        self.parent = parent
        self.sp = sp
        self.title = sp.name
        self.url = '%s/sp/%s' % (parent.url, sp.name)
        self.menu = [parent]
        self.back = parent.url

    def root_with_msg(self, message=None, message_type=None):
        return self._template('admin/option_config.html', title=self.title,
                              menu=self.menu, action=self.url, back=self.back,
                              message=message, message_type=message_type,
                              name='saml2_sp_%s_form' % (self.sp.name),
                              config=self.sp.get_config_obj())

    def GET(self, *args, **kwargs):
        return self.root_with_msg()

    def POST(self, *args, **kwargs):

        message = "Nothing was modified."
        message_type = "info"
        new_db_values = dict()

        conf = self.sp.get_config_obj()

        for name, option in conf.iteritems():
            if name in kwargs:
                value = kwargs[name]
                if isinstance(option, pconfig.List):
                    value = [x.strip() for x in value.split('\n')]
                    # for normal lists we want unordered comparison
                    if set(value) == set(option.get_value()):
                        continue
                elif isinstance(option, pconfig.Condition):
                    value = True
            else:
                if isinstance(option, pconfig.Condition):
                    value = False
                elif isinstance(option, pconfig.Choice):
                    value = list()
                    for a in option.get_allowed():
                        aname = '%s_%s' % (name, a)
                        if aname in kwargs:
                            value.append(a)
                elif isinstance(option, pconfig.MappingList):
                    current = deepcopy(option.get_value())
                    value = get_mapping_list_value(name,
                                                   current,
                                                   **kwargs)
                    # if current value is None do nothing
                    if value is None:
                        if option.get_value() is None:
                            continue
                        # else pass and let it continue as None
                elif isinstance(option, pconfig.ComplexList):
                    current = deepcopy(option.get_value())
                    value = get_complex_list_value(name,
                                                   current,
                                                   **kwargs)
                    # if current value is None do nothing
                    if value is None:
                        if option.get_value() is None:
                            continue
                        # else pass and let it continue as None
                else:
                    continue

            if value != option.get_value():
                cherrypy.log.error("Storing %s = %s" %
                                   (name, value), severity=logging.DEBUG)
                new_db_values[name] = value

        if len(new_db_values) != 0:
            try:
                # Validate user can make these changes
                for (key, value) in new_db_values.iteritems():
                    if key == 'Name':
                        if (not self.user.is_admin and
                                self.user.name != self.sp.owner):
                            raise UnauthorizedUser("Unauthorized to set owner")
                    elif key in ['Owner', 'Default NameID', 'Allowed NameIDs',
                                 'Attribute Mapping', 'Allowed Attributes']:
                        if not self.user.is_admin:
                            raise UnauthorizedUser(
                                "Unauthorized to set %s" % key
                            )

                # Make changes in current config
                for name, option in conf.iteritems():
                    value = new_db_values.get(name, False)
                    # A value of None means remove from the data store
                    if value is False or value == []:
                        continue
                    if name == 'Name':
                        if not self.sp.is_valid_name(value):
                            raise InvalidValueFormat(
                                'Invalid name! Use only numbers and'
                                ' letters'
                            )
                        self.sp.name = value
                        self.url = '%s/sp/%s' % (self.parent.url, value)
                        self.parent.rename_sp(option.get_value(), value)
                    elif name == 'User Owner':
                        self.sp.owner = value
                    elif name == 'Default NameID':
                        self.sp.default_nameid = value
                    elif name == 'Allowed NameIDs':
                        self.sp.allowed_nameids = value
                    elif name == 'Attribute Mapping':
                        self.sp.attribute_mappings = value
                    elif name == 'Allowed Attributes':
                        self.sp.allowed_attributes = value
            except InvalidValueFormat, e:
                message = str(e)
                message_type = ADMIN_STATUS_WARN
                return self.root_with_msg(message, message_type)
            except UnauthorizedUser, e:
                message = str(e)
                message_type = ADMIN_STATUS_ERROR
                return self.root_with_msg(message, message_type)
            except Exception as e:  # pylint: disable=broad-except
                self.debug("Error: %s" % repr(e))
                message = "Internal Error"
                message_type = ADMIN_STATUS_ERROR
                return self.root_with_msg(message, message_type)

            try:
                self.sp.save_properties()
                message = "Properties successfully changed"
                message_type = ADMIN_STATUS_OK
            except Exception as e:  # pylint: disable=broad-except
                self.error('Failed to save data: %s' % e)
                message = "Failed to save data!"
                message_type = ADMIN_STATUS_ERROR
            else:
                self.sp.refresh_config()

        return self.root_with_msg(message=message,
                                  message_type=message_type)

    def delete(self):
        self.parent.del_sp(self.sp.name)
        self.sp.permanently_delete()
        return self.parent.root()
    delete.public_function = True


class Saml2AdminPage(AdminPage):
    def __init__(self, site, config):
        super(Saml2AdminPage, self).__init__(site)
        self.name = 'admin'
        self.cfg = config
        self.providers = []
        self.menu = []
        self.url = None
        self.sp = AdminPage(self._site)

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
            self.debug("Failed to remove provider %s: %s" % (name, str(e)))

    def add_sps(self):
        if self.cfg.idp:
            for p in self.cfg.idp.get_providers():
                try:
                    sp = ServiceProvider(self.cfg, p)
                    self.del_sp(sp.name)
                    self.add_sp(sp.name, sp)
                except Exception, e:  # pylint: disable=broad-except
                    self.debug("Failed to find provider %s: %s" % (p, str(e)))

    def mount(self, page):
        self.menu = page.menu
        self.url = '%s/%s' % (page.url, self.name)
        self.add_sps()
        self.add_subtree('new', NewSPAdminPage(self._site, self))
        page.add_subtree(self.name, self)

    def root(self, *args, **kwargs):
        return self._template('admin/providers/saml2.html',
                              title='SAML2 Administration',
                              providers=self.providers,
                              baseurl=self.url,
                              menu=self.menu)
