import restapi
import json

class GetThirdPartyINFO():
    def __init__(self):
        self.v2_auth = {
                    'auth_url': 'http://api.inte.lenovo.com:5000/v2.0/',
                    'region_name': 'RegionOne',
                    'tenant_name':'admin',
                    'username': 'admin',
                    'password': 'admin',
                    }

        self.v3_auth = {
                'auth_url': 'http://api.inte.lenovo.com:5000/v3',
                'project_domain_name': 'Default',
                'user_domain_name': 'Default',
                'region_name': 'RegionOne',
                'project_name':'admin',
                'username': 'admin',
                'password': 'admin',
                }

        """
        n_api = restapi.ProtonAPI(**v2_auth)
        hosts = n_api.get()
        print "server:%s\n" % hosts
        print "\n\n"
        """

    def get_networksname_of_vm(self, vm_id=None):
        nova_api = restapi.NovaAPI(**self.v2_auth)
        servers = nova_api.client.servers.get(vm_id)
        #print  [s.to_dict() for s in servers]
        networks_name = servers.addresses.keys()
        return networks_name


    def get_vlan_of_networkname(self, network_name=None):
        args={
                "fields":['id','name']
        }
        neutron_api = restapi.NeutronAPI(**self.v2_auth)
        all_networks = neutron_api.client.list_networks( **args).get('networks')

        for network in all_networks:
            if network.get('name') == network_name:
                detail = neutron_api.client.show_network(network.get('id'))
                vlan_id = detail.get('network').get('provider:segmentation_id')
                return vlan_id



    def get_mac_of_hostinterface(self, host_name = None, interface = None):
        proton_api = restapi.ProtonAPI(**self.v2_auth)
        hosts = proton_api.client.list_hosts()
        for host in hosts:
            if host.get('sysname') == host_name:
                portdetails = host.get('activeportdetails')
                ports = json.loads(portdetails)
                for port in ports:
                    if port.get('eth_name') == interface:
                        print port.get('eth_mac')


def main():
    third = GetThirdPartyINFO()

    input_host = 'node-1'
    input_interface = 'eth0'
    third.get_mac_of_hostinterface(input_host, input_interface)

    vm_id = 'ac1411fb-570e-4a82-8173-92de54772182'
    networks_name = third.get_networksname_of_vm(vm_id)
    for network_name in networks_name:
        print network_name, third.get_vlan_of_networkname(network_name)


main()
