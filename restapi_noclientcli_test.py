#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import sys
import json
import uuid as uuid_util
from keystoneauth1 import access

def authenticate_keystone():

        username = 'admin'
        password = 'admin'
        creds = {'username': username,
                     'password': password}

        tenant_name = 'admin'
        body = {'auth': {'passwordCredentials': creds,
                   'tenantName': tenant_name,
                   },
               }

        headers={'Content-type': 'application/json',
                    'User-Agent': 'python-neutronclient'
                }
        print json.dumps(body)

        auth_url = 'http://api.inte.lenovo.com:5000/v2.0'
        token_url = auth_url + "/tokens"
        resp = requests.request('POST', token_url,
                                           data=json.dumps(body),
                                           headers=headers,
                                           verify=True,
                                           )
        resp_body = json.loads(resp.text)
        auth_ref = access.create(body=resp_body)
        return auth_ref.auth_token




def main():
    method="request.%s" % sys.argv[1]
    auth_token = authenticate_keystone()
    print auth_token

    if sys.argv[1] == "get":
        headers={'X-auth-token': auth_token}
        url = "http://127.0.0.1:9914/v2.0/troubleshooting%s" % (sys.argv[2])
        print url
        resp = requests.get(url, headers=headers)
        print resp.json()
    elif sys.argv[1] == "post":
        headers={'X-auth-token': auth_token}
        s = {'instance_id':'01234', 'name':'zeng'}
        url = "http://127.0.0.1:9914/v2.0/troubleshooting%s" % (sys.argv[2])
        print "post", url
        resp = requests.post(url, headers=headers, data=s)
        #resp = requests.post(url, json=s, verify=False)
        #resp = requests.post(url, headers=headers)
        print resp.json()

main()



def host():
    base_url = 'http://127.0.0.1:9080/v1'
    #r = requests.get(base_url+'server/list_hosts', verify=False)
    #r = requests.get(base_url+'server/system_statistics', verify=False)
    r = requests.get(base_url+'/v1/portmapping/showPortMappingNodes', verify=False)

    print r.json()

#host()




