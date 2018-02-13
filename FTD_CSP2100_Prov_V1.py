
#=========================================================================================================================#
# Provisioning the NGFWv with Day0 Configuration on CSP2100
#=========================================================================================================================#
 
import json
import sys
import requests
import urllib3 
import ssl
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from requests.auth import HTTPBasicAuth

server = "https://10.2.0.110"
 
username = "admin"
if len(sys.argv) > 1:
    username = sys.argv[1]
password = "123Cisco@123"
if len(sys.argv) > 2:
    password = sys.argv[2]
               
r = None
r1 = None
headers = {'Content-Type': 'application/vnd.yang.data+json'}

print "Zero Touch Provisioning of FTDv with Day0 Configuration file"
print ('\n' * 2)
 
api_path = "/api/running/services/"    # param
api_path1 = "/api/running/services/service/Ten0FMC05"    # param
url = server + api_path
if (url[-1] == '/'):
    url = url[:-1]

url1 = server + api_path1
if (url[-1] == '/'):
    url1 = url1[:-1]
 

# POST and PATCH OPERATION
 
post_data = {"service":
{
    "name":"Ten0FMC05",
    "ip":"10.2.0.112",
    "disk_size":"50",
    "iso_name":"Cisco_Firepower_Threat_Defense_Virtual-6.2.2-81.qcow2",
    "memory":"8192",
    "vnics":{"vnic":
             [
                 {"nic":"0", "type":"access", "model":"virtio", "network_name":"enp1s0f0"},
                 {"nic":"1", "type":"access", "model":"virtio", "network_name":"enp1s0f0"},
                 {"nic":"2", "type":"access", "model":"virtio", "vlan":"510", "network_name":"enp7s0f1"},
                 {"nic":"3", "type":"access", "model":"virtio", "vlan":"520", "network_name":"enp7s0f1"},
                 {"nic":"4", "type":"access", "model":"virtio", "vlan":"530", "network_name":"enp7s0f1"}
                 ]
             },
    "disk_type":"virtio", "day0_filename":"day0.iso", "day0-dest-filename":"day0.iso"
}
             }

patch_data = {"service":
              {
               "numcpu":"4",
               "power":"on"
               }
              }

  
try:
    # REST call with SSL verification turned off:

    r = requests.post(url, data=json.dumps(post_data), headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    r1 = requests.patch(url1, data=json.dumps(patch_data), headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)

    status_code = r.status_code
    status_code1 = r1.status_code
    
    #print("Status code is: "+str(status_code))
    #print("status code is: "+str(status_code1))
    if status_code == 201 or status_code == 202 or status_code1 == 201 or status_code1 == 202:
        print ("Provisoning of vFTD is successful...")
        print ('\n' * 2)
        print ("Please give me sometime for the vFTD to bootup successfully")
    else :
        r1.raise_for_status()
        print ("Error occurred in POST -->" +str(status_code))
        print ("Error occurred in POST --> "+str(status_code))
except requests.exceptions.HTTPError as err:
    print ("Error in connection --> "+str(err))
finally:
    if r: r.close()
    if r1: r1.close()



import time
print ('\n' * 2)
print ("Waiting for FTDv to Boot up")
time.sleep(1070)


import os
if os.system("ping -n 10 10.2.0.112") == 0:
    print "FTDv is Active"
else:
    pingstatus = "FTDv is not Active"
    print "FTDv is not Active"
    print ('\n' * 2)

#=========================================================================================================================#
# Registering the NGFWv with default policy in Firepower Management Center (FMC)#
#=========================================================================================================================#
 
import json
import sys
import requests
import urllib3 
import ssl
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
 
server = "https://10.0.13.102"
 
username = "admin"
if len(sys.argv) > 1:
    username = sys.argv[1]
password = "Cisco123"
if len(sys.argv) > 2:
    password = sys.argv[2]
               
r = None
r1 = None 
headers = {'Content-Type': 'application/json'}
api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
auth_url = server + api_auth_path
try:
    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    auth_headers = r.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    if auth_token == None:
        print("auth_token not found. Exiting...")
        sys.exit()
except Exception as err:
    print ("Error in generating auth token --> "+str(err))
    sys.exit()
 
headers['X-auth-access-token']=auth_token

api_path_1 = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies"    # param
url = server + api_path_1
if (url[-1] == '/'):
    url = url[:-1]
 

 

# GET OPERATION

try:
    # REST call with SSL verification turned off: 
    r = requests.get(url, headers=headers, verify=False)
    status_code = r.status_code
    resp_1 = r.text
    if (status_code == 200):
        print("GET successful. Response data --> ")
        json_resp_1 = json.loads(resp_1)
        print(json.dumps(json_resp_1,sort_keys=True,indent=4, separators=(',', ': ')))
        print(json.dumps(json_resp_1['items'][0]['id']))



  # POST OPERATION

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords"    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]


    post_data = {
        "name": "10.2.0.112",
        "hostName": "10.2.0.112",
        "regKey": "Cisco123",
        "type": "Device",
        "version": "6.2.2",
        "license_caps": [
            "BASE",
            "MALWARE",
            "URLFilter",
    "THREAT"
            ],
        "accessPolicy": {
            "type": "PolicyAssignment",
            "id": json_resp_1['items'][0]['id']
            }
        }
    try:
    # REST call with SSL verification turned off:
     r1 = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
    
     status_code = r1.status_code
     resp = r1.text
    #print("Status code is: "+str(status_code))
     if status_code == 201 or status_code == 202:
        print ("FTDv registration with default policy is in Progress...")
        print ('\n' * 2)
        json_resp = json.loads(resp)
        print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
     else :
        r1.raise_for_status()
        print ("Error occurred in POST --> "+resp)
    except requests.exceptions.HTTPError as err:
     print ("Error in connection --> "+str(err))
finally:
    if r: r.close()
               

import time
print ('\n' * 2)
print ("Waiting for FTDv to get registered")
time.sleep(120)
print ('\n' * 2)
print ("FTDv registration is done")

#=========================================================================================================================#
#Configuring the Interfaces with IP addresses and bring up the interfaces#
#=========================================================================================================================#

 
import json
import sys
import requests
import urllib3 
import ssl
import time
import datetime 
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
 
 
server = "https://10.0.13.102"
 
username = "admin"
if len(sys.argv) > 1:
    username = sys.argv[1]
password = "Cisco123"
if len(sys.argv) > 2:
    password = sys.argv[2]
               
r = None
r1 = None
r2 = None
device = None
headers = {'Content-Type': 'application/json'}
api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
auth_url = server + api_auth_path
try:
    
    # REST call with SSL verification turned off: 
    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    
    auth_headers = r.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    if auth_token == None:
        print("auth_token not found. Exiting...")
        sys.exit()
except Exception as err:
    print ("Error in generating auth token --> "+str(err))
    sys.exit()
 
headers['X-auth-access-token']=auth_token
 
api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords"    # param



url = server + api_path
if (url[-1] == '/'):
    url = url[:-1]
 
# GET OPERATION
 


try:
    # REST call with SSL verification turned off: 
    r = requests.get(url, headers=headers, verify=False)
    
    status_code = r.status_code
    resp_0 = r.text
    
    if (status_code == 200):
        print("GET successful for Device ID -->  ")
        json_resp_0 = json.loads(resp_0)
        print(json.dumps(json_resp_0,sort_keys=True,indent=4, separators=(',', ': ')))
        print (json_resp_0['items'][0]['id'])

        d = json_resp_0['items'][0]['id']

        url0 = url +  "/" + d + "/physicalinterfaces"

        if (url0[-1] == '/'):
            url0 = url0[:-1]

        r1 = requests.get(url0, headers=headers, verify=False)

        resp1 = r1.text

        if (r1.status_code == 200):
            print("GET successful for Interfaces ID --> ")
            json_resp1 = json.loads(resp1)

            #for i in range(0, len (json_resp1['items'])):
            url1 = json_resp1['items'][0]['links']['self']
            #print url1

            put_data = {
                "type": "PhysicalInterface",
                "MTU": 9000,
                "managementOnly": "false",
                "ipv4": {
                    "static": {
                        "address": "10.1.0.10",
                        "netmask": "24"
                        }
                    },
                "mode": "NONE",
                "ifname": "inside",
                "enabled": "true",
                "name": "GigabitEthernet0/0",
                "id": json_resp1['items'][0]['id']
                }

            url2 = json_resp1['items'][1]['links']['self']
            #print url2
            put_data1 = {
                "type": "PhysicalInterface",
                "MTU": 9000,
                "managementOnly": "false",
                "ipv4": {
                    "static": {
                        "address": "10.1.1.10",
                        "netmask": "24"
                        }
                    },
                "mode": "NONE",
                "ifname": "outside",
                "enabled": "true",
                "name": "GigabitEthernet0/1",
                "id": json_resp1['items'][1]['id']
                }
            
            r2 = requests.put(url1, data=json.dumps(put_data), headers=headers, verify=False)
            resp2 = r2.text
            json_resp2 = json.loads(resp2)
            print(json.dumps(json_resp2,sort_keys=True,indent=4, separators=(',', ': ')))
            print ('\n' * 2) 

            r3 = requests.put(url2, data=json.dumps(put_data1), headers=headers, verify=False)
            resp3 = r3.text
            json_resp3 = json.loads(resp3)
            print(json.dumps(json_resp3,sort_keys=True,indent=4, separators=(',', ': ')))
            print ('\n' * 2)

            print "Deploying the FTDv Device with changes"
            api_path_deploy = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deploymentrequests"
            url_deploy = server + api_path_deploy

            import time
            from time import time
            time_in_seconds = int(time())
            nowtime = int(time_in_seconds *1000)
            print ('"{}"'.format(nowtime))

            deploy_data = {
                "type": "DeploymentRequest",
                "version": nowtime,
                "forceDeploy": True,
                "ignoreWarning": True,
                "deviceList": [
                    d
                    ]
                }
            deploy = requests.post(url_deploy, data=json.dumps(deploy_data), headers=headers, verify=False)
            deploy_resp = deploy.text
            json_deploy = json.loads(deploy_resp)
            print(json.dumps(json_deploy,sort_keys=True,indent=4, separators=(',', ': ')))

            print "The Zero Touch Provisioning is completed, and you should see the successful ping from Client to Web"
            print ('\n' * 2)
            print "To permit the HTTP access to the Web Server from client, you need to add a rule"

    else:
        r.raise_for_status()
        print("Error occurred in GET --> "+resp)

        
                  
except requests.exceptions.HTTPError as err:
    print ("Error in connection --> "+str(err))

    
finally:
    if r : r.close()


#=========================================================================================================================#
#Additional Rule in the default policy to allow the HTTP traffic from Client to Web Server.#
#=========================================================================================================================#


try:
    input("Press enter to add a rule to allow HTTP traffic from Cliet to Web server")
except SyntaxError:
    pass

#
# Generated FMC REST API sample script#
#
 
import json
import sys
import requests
import urllib3
import ssl
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

 
server = "https://10.0.13.102"
 
username = "admin"
if len(sys.argv) > 1:
    username = sys.argv[1]
password = "Cisco123"
if len(sys.argv) > 2:
    password = sys.argv[2]
               
r = None
r_device = None
deploy = None
r1 = None
r_1 = None

headers = {'Content-Type': 'application/json'}
api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
auth_url = server + api_auth_path
try:
    
    # REST call with SSL verification turned off: 
    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    
    auth_headers = r.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    if auth_token == None:
        print("auth_token not found. Exiting...")
        sys.exit()
except Exception as err:
    print ("Error in generating auth token --> "+str(err))
    sys.exit()
 
headers['X-auth-access-token']=auth_token
 

api_path_1 = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies"    # param
url_1 = server + api_path_1
if (url_1[-1] == '/'):
    url_1 = url_1[:-1]
 

api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/protocolportobjects"    # param
url = server + api_path
if (url[-1] == '/'):
    url = url[:-1]
 

# GET OPERATION

try:
    # REST call with SSL verification turned off: 
    r_1 = requests.get(url_1, headers=headers, verify=False)
    status_code = r_1.status_code
    resp_1 = r_1.text
    if (status_code == 200):
        print("GET successful. Response data --> ")
        json_resp_1 = json.loads(resp_1)
        print(json.dumps(json_resp_1,sort_keys=True,indent=4, separators=(',', ': ')))
        print(json.dumps(json_resp_1['items'][0]['id']))

        accesspolicy = json_resp_1['items'][0]['id']

        #api_path_1 = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/005056B8-5B2A-0ed3-0000-004294967299/accessrules"    # param

        api_path_2 = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + accesspolicy + "/accessrules"    # param

        print api_path_2

    status_code = r_1.status_code


    # REST call with SSL verification turned off:
    r = requests.get(url, headers=headers, verify=False)
    resp = r.text
    if (status_code == 200):
        print("GET successful. Protocol Port Objects --> ")
        
        json_resp = json.loads(resp)

        rule_data = {
            "action": "ALLOW",
            "enabled": True,
            "type": "AccessRule",
            "name": "Rule03",
            "sendEventsToFMC": True,
            "logFiles": True,
            "logBegin": True,
            "logEnd": True,
            "destinationPorts": {
                "objects": [
                    {
                        "type": "ProtocolPortObject",
                        "name": "HTTP",
                        "id": json_resp['items'][5]['id']
                        }
                    ]
                }
            }

        
        url1 = server + api_path_2
        if (url1[-1] == '/'):
            url1 = url1[:-1]

        r1 = requests.post(url1, data=json.dumps(rule_data), headers=headers, verify=False)
        resp1 = r1.text
        json_resp1 = json.loads(resp1)
        print(json.dumps(json_resp1,sort_keys=True,indent=4, separators=(',', ': ')))
        print ('\n' * 2)

        path_device = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords"    # param
        url_device = server + path_device
        r_device = requests.get(url_device, headers=headers, verify=False)
        resp_device = r_device.text
        json_resp_device = json.loads(resp_device)
        print(json.dumps(json_resp_device,sort_keys=True,indent=4, separators=(',', ': ')))

        d = json_resp_device['items'][0]['id']
        print d

        import time
        time.sleep(10)

        print "Deployting the Device with changes"
        api_path_deploy = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deploymentrequests"
        url_deploy = server + api_path_deploy

        if (url_deploy[-1] == '/'):
            url_deploy = url_deploy[:-1]
        
        import time
        from time import time
        time_in_seconds = int(time())
        nowtime = int(time_in_seconds *1000)
        print ('"{}"'.format(nowtime))


        deploy_data = {
            "type": "DeploymentRequest",
            "version": nowtime,
            "forceDeploy": True,
            "ignoreWarning": True,
            "deviceList": [
                d
                ]
            }
        deploy = requests.post(url_deploy, data=json.dumps(deploy_data), headers=headers, verify=False)
        deploy_resp = deploy.text
        json_deploy = json.loads(deploy_resp)
        print(json.dumps(json_deploy,sort_keys=True,indent=4, separators=(',', ': ')))
        
        import time
        time.sleep(120)
        print " Deployment of the HTTP access rule completed successfully"
    else:
        r.raise_for_status()
        print("Error occurred in GET --> "+resp)
except requests.exceptions.HTTPError as err:
    print ("Error in connection --> "+str(err)) 
finally:
    if r : r.close()



            
