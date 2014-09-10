#!/usr/bin/python
#
# Copyright (C) 2014  Ipsilon project Contributors, for licensee see COPYING

from ipsilon.util.data import TranStore
from ipsilon.util.log import Log
from datetime import datetime
from ipsilon.util.cookies import SecureCookie


TRANSTABLE = 'transactions'
TRANSID = "ipsilon_transaction_id"


class Transaction(Log):

    def __init__(self, provider, **kwargs):
        self.debug('Transaction: %s' % repr(kwargs))
        self.provider = provider
        self.transaction_id = None
        self._ts = TranStore()
        self.cookie = None
        tid = kwargs.get(TRANSID)
        if tid:
            self.transaction_id = tid
            data = self._ts.get_unique_data(TRANSTABLE, tid)
            self._get_cookie()
        else:
            data = {'provider': self.provider,
                    'origintime': str(datetime.now())}
            self.transaction_id = self._ts.new_unique_data(TRANSTABLE, data)
            self._set_cookie()
        self.debug('Transaction id: %s' % self.transaction_id)

    def _set_cookie(self):
        self.cookie = SecureCookie(name=None, value=self.provider)
        self.cookie.send()
        cookiedata = {'cookie': self.cookie.name}
        data = {self.transaction_id: cookiedata}
        self._ts.save_unique_data(TRANSTABLE, data)

    def _get_cookie(self):
        data = self.retrieve()
        if 'cookie' not in data:
            raise ValueError('Cookie name not available')
        self.cookie = SecureCookie(data['cookie'])
        self.cookie.receive()
        if self.cookie.value is None:
            raise ValueError('Missing or invalid cookie')

    def _del_cookie(self):
        self.cookie.delete()

    def wipe(self):
        if not self.transaction_id:
            return
        self._ts.del_unique_data(TRANSTABLE, self.transaction_id)
        self._del_cookie()
        self.transaction_id = None

    def store(self, data):
        savedata = {self.transaction_id: data}
        self._ts.save_unique_data(TRANSTABLE, savedata)

    def retrieve(self):
        data = self._ts.get_unique_data(TRANSTABLE,
                                        uuidval=self.transaction_id)
        return data.get(self.transaction_id)

    def get_GET_arg(self):
        return "%s=%s" % (TRANSID, self.transaction_id)

    def get_POST_tuple(self):
        return (TRANSID, self.transaction_id)
