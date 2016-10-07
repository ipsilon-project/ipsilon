# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

import cherrypy
from ipsilon.util import config as pconfig
from ipsilon.admin.common import AdminPage
from ipsilon.admin.common import ADMIN_STATUS_OK
from ipsilon.admin.common import ADMIN_STATUS_ERROR
from ipsilon.admin.common import ADMIN_STATUS_WARN
from ipsilon.admin.common import get_mapping_list_value
from ipsilon.admin.common import get_complex_list_value
from ipsilon.providers.openidc.provider import (Client,
                                                InvalidMetadata,
                                                InvalidRedirectURI)
from copy import deepcopy
import logging
import re


INVALID_IN_CLIENT_ID = r'[^a-zA-Z0-9\-\.]'


class ClientAdminPage(AdminPage):

    def __init__(self, client, site, parent):
        super(ClientAdminPage, self).__init__(site, form=True)
        self.parent = parent
        self.client = Client(client)
        self.title = self.client.client_id or 'New client'
        if self.client.client_id:
            self.new_client = False
            self.url = '%s/client/%s' % (parent.url,
                                         self.client.client_id)
        else:
            self.new_client = True
            self.url = '%s/new' % parent.url
        self.menu = [parent]
        self.back = parent.url

    def root_with_msg(self, message=None, message_type=None):
        return self._template('admin/option_config.html', title=self.title,
                              menu=self.menu, action=self.url, back=self.back,
                              message=message, message_type=message_type,
                              name='openidc_client_form',
                              config=self.client.get_config_obj())

    def GET(self, *args, **kwargs):
        if not self.user.is_admin:
            raise cherrypy.HTTPError(403)

        return self.root_with_msg()

    def POST(self, *args, **kwargs):
        if not self.user.is_admin:
            raise cherrypy.HTTPError(403)

        message = "Nothing was modified."
        message_type = "info"
        new_db_values = dict()

        conf = self.client.get_config_obj()

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

            if value != option.get_value() and name not in ['Client ID']:
                cherrypy.log.error("Storing %s = %s" %
                                   (name, value), severity=logging.DEBUG)
                new_db_values[name] = value

        client_id = kwargs.get('Client ID')
        if self.new_client and client_id:
            if re.search(INVALID_IN_CLIENT_ID, client_id):
                message = 'Invalid character in client ID'
                message_type = ADMIN_STATUS_WARN
                return self.root_with_msg(message, message_type)
            elif client_id.startswith('D-'):
                # This is not allowed, as the D- is the internal indicator that
                # this is a client registered via dynamic registration
                message = 'Client ID cannot start with D-'
                message_type = ADMIN_STATUS_WARN
                return self.root_with_msg(message, message_type)
            elif self.parent.cfg.datastore.getClient(client_id):
                message = 'Client with this client ID already exists'
                message_type = ADMIN_STATUS_WARN
                return self.root_with_msg(message, message_type)

        if self.new_client or len(new_db_values) != 0:
            try:
                for key in new_db_values:
                    conf[key].set_value(new_db_values[key])
                self.client.validate()
            except InvalidMetadata as e:
                message = 'Value error: %s' % str(e)
                message_type = ADMIN_STATUS_WARN
                return self.root_with_msg(message, message_type)
            except pconfig.FieldValueError as e:
                message = 'Field %s incorrect: %s' % (e.field, str(e))
                message_type = ADMIN_STATUS_WARN
                return self.root_with_msg(message, message_type)
            except InvalidRedirectURI as e:
                message = 'Redirect URI incorrect: %s' % str(e)
                message_type = ADMIN_STATUS_WARN
                return self.root_with_msg(message, message_type)
            except Exception as e:  # pylint: disable=broad-except
                self.debug("Error: %s" % repr(e))
                message = "Internal Error: %s" % repr(e)
                message_type = ADMIN_STATUS_ERROR
                return self.root_with_msg(message, message_type)

            try:
                metadata = self.client.generate()
                if self.new_client:
                    cid = self.parent.cfg.datastore.registerStaticClient(
                        client_id, metadata)
                    message = "Client created"
                else:
                    self.parent.cfg.datastore.updateClient(
                        self.client.client_id, metadata)
                    message = "Properties successfully changed"
                message_type = ADMIN_STATUS_OK
            except Exception as e:  # pylint: disable=broad-except
                self.error('Failed to save data: %s' % e)
                message = "Failed to save data!"
                message_type = ADMIN_STATUS_ERROR
                return self.root_with_msg(message=message,
                                          message_type=message_type)

        if self.new_client:
            raise cherrypy.HTTPRedirect('%s/client/%s'
                                        % (self.parent.url, cid))
        else:
            return self.root_with_msg(message=message,
                                      message_type=message_type)

    def delete(self):
        if not self.user.is_admin:
            raise cherrypy.HTTPError(403)

        if not self.parent.cfg.datastore.deleteClient(self.client.client_id):
            raise Exception('Deleting the client did not work')
        raise cherrypy.HTTPRedirect(self.parent.url)
    delete.public_function = True


class DynamicAdminPage(AdminPage):
    def __init__(self, site, main):
        super(DynamicAdminPage, self).__init__(site)
        self.name = 'client'
        self.main = main

    def index(self):
        return self.unknown_client()

    def root(self, *args, **kwargs):
        return self.unknown_client()

    def mount(self, page):
        pass

    def unknown_client(self):
        raise cherrypy.HTTPRedirect('%s/admin/providers/openidc/admin'
                                    % self.basepath)
    unknown_client.exposed = True

    def __getattr__(self, attr):
        client = self.main.cfg.datastore.getClient(attr)
        if client is None:
            return self.unknown_client()
        # pylint: disable=protected-access
        return ClientAdminPage(client, self.main._site, self.main)


class OpenIDCAdminPage(AdminPage):
    def __init__(self, site, config):
        super(OpenIDCAdminPage, self).__init__(site)
        self.name = 'admin'
        self.cfg = config
        self.menu = []
        self.url = None
        self.client = DynamicAdminPage(self._site, self)

    def mount(self, page):
        self.menu = page.menu
        self.url = '%s/%s' % (page.url, self.name)
        self.add_subtree('new', ClientAdminPage({}, self._site, self))
        page.add_subtree(self.name, self)

    @property
    def clients(self):
        stc_clients = self.cfg.datastore.getStaticClients()
        dyn_clients = self.cfg.datastore.getDynamicClients()
        # Since all dynamic clients start with D-, and all static clients start
        # with something else, it is safe to just update one with the other.
        all_clients = stc_clients
        all_clients.update(dyn_clients)
        return all_clients

    def root(self, *args, **kwargs):
        return self._template('admin/providers/openidc.html',
                              title='OpenID Connect Administration',
                              clients=self.clients,
                              baseurl=self.url,
                              menu=self.menu)
