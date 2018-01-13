#!/usr/bin/env python
# -*- coding: utf-8 -*-

from keystoneauth1 import loading, session
from novaclient import client as nova_client
from glanceclient import client as glance_client
from cinderclient import client as cinder_client
from neutronclient.v2_0 import client as neutron_clientv20
from protonclient.v2_0 import client as proton_clientv20

"""
    Usage:

        v3_auth = {
            'auth_url': 'http://api.inte.lenovo.com:5000/v3',
            'project_domain_name': 'Default',
            'user_domain_name': 'Default',
            'user_domain_name': 'Default',
            'region_name': 'RegionOne',
            'project_name':'admin',
            'username': 'admin',
            'password': 'admin',
        }
        n_api = NovaAPI(**v3_auth)
        servers = n_api.get_all()

        v2_auth = {
            'auth_url': 'http://api.inte.lenovo.com:5000/v2.0/',
            'region_name': 'RegionOne',
            'tenant_name':'admin',
            'username': 'admin',
            'password': 'admin',
        }
        n_api = NovaAPI(**v2_auth)
        servers = n_api.get_all()
"""


class Base(object):

    def __init__(self, auth_plugin='password', **auth_info):
        self._session = None
        self.auth_plugin = auth_plugin
        self.auth_info = auth_info

    @property
    def _load_auth_plugin(self):
        loader = loading.get_plugin_loader(self.auth_plugin)
        return loader.load_from_options(**self.auth_info)

    @property
    def auth_session(self):

        if not self._session:
            self._session = session.Session(auth=self._load_auth_plugin)
        return self._session

    @property
    def client(self):
        raise NotImplementedError()


class NovaAPI(Base):

    def __init__(self, version=2,
                 region_name='',
                 **kwargs):
        self.version = version
        self.region_name = region_name
        super(NovaAPI, self).__init__(**kwargs)

    @property
    def client(self):
        return nova_client.Client(self.version,
                                  session=self.auth_session,
                                  region_name=self.region_name)

    def get(self, server_id):
        item = self.client.servers.get(server_id)
        return item

    def get_all(self, search_opts=None):
        search_opts = search_opts or {}
        items = self.client.servers.list(detailed=True,
                                         search_opts=search_opts)
        return items


class CinderAPI(Base):

    def __init__(self, version=2,
                 region_name='',
                 **kwargs):
        self.version = version
        self.region_name = region_name
        super(CinderAPI, self).__init__(**kwargs)

    @property
    def client(self):
        return cinder_client.Client(self.version,
                                    session=self.auth_session,
                                    region_name=self.region_name)

    def get(self, volume_id):
        item = self.client.volumes.get(volume_id)
        return item

    def get_all(self, search_opts=None):
        search_opts = search_opts or {}
        items = self.client.volumes.list(detailed=True,
                                         search_opts=search_opts)
        return items


class NeutronAPI(Base):

    def __init__(self,
                 region_name='',
                 **kwargs):
        self.region_name = region_name
        super(NeutronAPI, self).__init__(**kwargs)

    @property
    def client(self):
        return neutron_clientv20.Client(session=self.auth_session,
                                        region_name=self.region_name)

    def get(self, network_uuid):
        return self.client.show_network(network_uuid).get('network') or {}

    def get_all(self):
        return self.client.list_networks().get('networks')

    def port_list(self, **kwargs):
        return self.client.list_ports(**kwargs).get('ports')

    def port_show(self, network_uuid):
        return self.client.show_port(network_uuid).get('port') or {}

    def floatingip_list(self, **search_opts):
        return self.client.list_floatingips(**search_opts).get('floatingips')

class ProtonAPI(Base):

    def __init__(self,
                 region_name='',
                 **kwargs):
        self.region_name = region_name
        super(ProtonAPI, self).__init__(**kwargs)

    @property
    def client(self):
        return proton_clientv20.Client(session=self.auth_session,
                                        region_name=self.region_name)

    def get(self):
        return self.client.list_hosts()

