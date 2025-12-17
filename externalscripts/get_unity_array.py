#!/usr/bin/python3
"""
Author: Morris (@geekzu)
Contributor: Simon Jackson (@sjackson0109)
Created: 2025/01/23
Updated: 2025/12/17
Version: 1.7
Description:
 - Connects to an EMC Unity 380 series storage array via REST API.
 - Authenticates using provided credentials and establishes a session.
 - Discovers and monitors resources such as LUNs, pools, ports, disks, and system components.
 - Collects health, status, and performance metrics (e.g., link status, disk health, pool usage).
 - Formats collected data into Zabbix-compatible JSON for monitoring and alerting.
 - Sends data to a Zabbix server using zabbix_sender.
 - Supports two modes: resource discovery and status monitoring.
 - Logs all actions and errors for troubleshooting and auditing.
"""
import os
import time
import argparse
import sys
import json
import subprocess
import logging
import logging.handlers
import requests
import urllib3

# TLS verify from environment variable UNITY_TLS_VERIFY (default is 0 = ignore certs, likely self-signed)
tls_verify = os.environ.get('UNITY_TLS_VERIFY', '0') == '1'

from requests.packages.urllib3.exceptions import InsecureRequestWarning
if not tls_verify:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Create log-object
LOG_FILENAME = "/tmp/unity_state.log"
unity_logger = logging.getLogger("unity_logger")
unity_logger.setLevel(logging.INFO)

# Set handler
unity_handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=1024*1024, backupCount=5)
unity_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Set formatter for handler
unity_handler.setFormatter(unity_formatter)

# Add handler to log-object
unity_logger.addHandler(unity_handler)

def api_connect(api_user, api_password, api_ip, api_port):
    api_login_url = f"https://{api_ip}:{api_port}/api/types/loginSessionInfo"
    session_unity = requests.Session()
    session_unity.auth = (api_user, api_password)
    session_unity.headers = {'X-EMC-REST-CLIENT': 'true', 'Content-type': 'application/json', 'Accept': 'application/json'}

    try:
        login = session_unity.get(api_login_url, verify=False)
    except Exception as oops:
        unity_logger.error(f"Connection Error Occurs: {oops}")
        sys.exit("50")

    if login.status_code != 200:
        unity_logger.error(f"Connection Return Code = {login.status_code}")
        sys.exit("60")
    elif "isPasswordChangeRequired" in login.text:  # If string "isPasswordChangeRequired" is found, login is successful
        unity_logger.info("Connection established")
        return session_unity
    else:
        unity_logger.error("Login Something went wrong")
        sys.exit("70")

def api_logout(api_ip, session_unity):
    api_logout_url = f"https://{api_ip}/api/types/loginSessionInfo/action/logout"
    session_unity.headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

    try:
        logout = session_unity.post(api_logout_url, verify=False)
    except Exception as oops:
        unity_logger.error(f"Logout Error Occurs: {oops}")
        sys.exit("150")

    if logout.status_code != 200:
        unity_logger.error(f"Logout status = {logout.status_code}")
        sys.exit("160")
    elif "Logout successful" in logout.text:
        unity_logger.info("Logout successful")
    else:
        unity_logger.error("Logout Something went wrong")
        sys.exit("170")

def convert_to_zabbix_json(data):
    return json.dumps({"data": data}, indent=None, separators=(',', ': '))

def send_data_to_zabbix(zabbix_data, storage_name):
    sender_command = "/usr/bin/zabbix_sender"
    config_path = "/etc/zabbix/zabbix_agentd.conf"
    time_of_create_file = int(time.time())
    temp_file = f"/tmp/{storage_name}_{time_of_create_file}.tmp"

    with open(temp_file, "w") as f:
        f.write("\n".join(zabbix_data))

    send_code = subprocess.call([sender_command, "-vv", "-c", config_path, "-s", storage_name, "-T", "-i", temp_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.remove(temp_file)
    return send_code

def discovering_resources(api_user, api_password, api_ip, api_port, storage_name, list_resources):
    api_session = api_connect(api_user, api_password, api_ip, api_port)

    xer = []
    try:
        for resource in list_resources:
            if ['disk'].count(resource) == 1:
                resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,model,serialNumber,sizeTotal,firmwareVersion".format(api_ip, api_port, resource)
                    #tierType,rpm,rawSize,vendorSize,diskTechnology,name,model,manufacturer,diskGroup[name],vendorSize,bank,bankSlotNumber,bankSlot
            elif ['pool'].count(resource) == 1:
                resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,sizeTotal,sizeUsed,sizeSubscribed".format(api_ip, api_port, resource)
            elif ['filesystem'].count(resource) == 1:
                resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,sizeTotal,sizeUsed,sizeAllocated".format(api_ip, api_port, resource)
            elif ['lun'].count(resource) == 1:
                resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,sizeTotal,sizeAllocated".format(api_ip, api_port, resource)
            else:
                resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name".format(api_ip, api_port, resource)
            
            resource_info = api_session.get(resource_url, verify=False)
            resource_info = json.loads(resource_info.content.decode('utf8'))
            
            discovered_resource = []
            for one_object in resource_info['entries']:
                if ['lun', 'pool' , 'filesystem'].count(resource) == 1:
                    one_object_list = {}
                    one_object_list["{#ID}"] = one_object['content']['id']
                    one_object_list["{#NAME}"] = one_object['content']['name'].replace(' ', '_')
                    one_object_list["{#SIZETOTAL}"] = one_object['content']['sizeTotal'].replace(' ', '_')
                    discovered_resource.append(one_object_list)
                elif ['disk'].count(resource) == 1:
                    one_object_list = {}
                    one_object_list["{#ID}"] = one_object['content']['id']
                    one_object_list["{#NAME}"] = one_object['content']['name'].replace(' ', '_')
                    one_object_list["{#MODEL}"] = one_object['content']['model'].replace(' ', '_')
                    one_object_list["{#SERIAL}"] = one_object['content']['serialNumber']
                    one_object_list["{#CAPACITY}"] = one_object['content']['sizeTotal']
                    one_object_list["{#FIRMWARE}"] = one_object['content']['firmwareVersion']
                    discovered_resource.append(one_object_list)
                else:
                    one_object_list = {}
                    one_object_list["{#ID}"] = one_object['content']['id']
                    one_object_list["{#NAME}"] = one_object['content']['name'].replace(' ', '_')
                    discovered_resource.append(one_object_list)
            converted_resource = convert_to_zabbix_json(discovered_resource)
            timestampnow = int(time.time())
            xer.append("%s %s %s %s" % (storage_name, resource, timestampnow, converted_resource))
    except Exception as oops:
        unity_logger.error("{0} Error occurs in discovering".format(api_ip))
        sys.exit("1000")

    api_session_logout = api_logout(api_ip, api_session)
    return send_data_to_zabbix(xer, storage_name)

def get_status_resources(api_user, api_password, api_ip, api_port, storage_name, list_resources):
    api_session = api_connect(api_user, api_password, api_ip, api_port)

    state_resources = [] # This list will persist state of resources (pool, lun, fcPort, battery, diks, ...) on zabbix format
    try:
        for resource in list_resources:
            # Create different URI for different resources
            if ['pool'].count(resource) == 1:
                resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,sizeTotal,sizeUsed,sizeSubscribed".format(api_ip, api_port, resource)
            elif ['filesystem'].count(resource) == 1:
                resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,sizeTotal,sizeUsed,sizeAllocated".format(api_ip, api_port, resource)
            elif ['lun'].count(resource) == 1:
                resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,sizeTotal,sizeAllocated".format(api_ip, api_port, resource)
            else:
                resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,needsReplacement".format(api_ip, api_port, resource)

            # Get info about one resource
            resource_info = api_session.get(resource_url, verify=False)
            resource_info = json.loads(resource_info.content.decode('utf8'))
            timestampnow = int(time.time())

            if ['ethernetPort', 'fcPort', 'sasPort'].count(resource) == 1:
                for one_object in resource_info['entries']:
                    key_health = "health.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
                    key_status = "link.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
                    state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))

                    # Get state of interfaces from description
                    descriptionIds = str(one_object['content']['health']['descriptionIds'][0]) # Convert description to string
                    if descriptionIds.find("LINK_UP") >= 0: # From description i can known, link is up or link is down
                        link_status = 10
                    elif descriptionIds.find("LINK_DOWN_NOT_IN_USE") >=0: #长文本匹配顺序要在LINK_DOWN之前
                        link_status = 12
                    elif descriptionIds.find("LINK_DOWN") >=0: 
                        link_status = 11
                    else:
                        link_status = 13 #增加了未知状态匹配

                    state_resources.append("%s %s %s %s" % (storage_name, key_status, timestampnow, link_status))

            elif ['lun'].count(resource) == 1:
                for one_object in resource_info['entries']:
                    key_health = "health.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_')) # Use lun name instead lun id on zabbix key
                    key_sizeTotal = "sizeTotal.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
                    key_sizeAllocated = "sizeAllocated.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))

                    state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
                    state_resources.append("%s %s %s %s" % (storage_name, key_sizeTotal, timestampnow, one_object['content']['sizeTotal']))
                    state_resources.append("%s %s %s %s" % (storage_name, key_sizeAllocated, timestampnow, one_object['content']['sizeAllocated']))
            elif ['pool'].count(resource) == 1:
                for one_object in resource_info['entries']:
                    key_health = "health.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_')) # Use pool name instead pool id on zabbix key
                    key_sizeUsedBytes = "sizeUsedBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
                    key_sizeTotalBytes = "sizeTotalBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
                    key_sizeSubscribedBytes = "sizeSubscribedBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))

                    state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
                    state_resources.append("%s %s %s %s" % (storage_name, key_sizeUsedBytes, timestampnow, one_object['content']['sizeUsed']))
                    state_resources.append("%s %s %s %s" % (storage_name, key_sizeTotalBytes, timestampnow, one_object['content']['sizeTotal']))
                    state_resources.append("%s %s %s %s" % (storage_name, key_sizeSubscribedBytes, timestampnow, one_object['content']['sizeSubscribed']))
            elif ['filesystem'].count(resource) == 1:
                for one_object in resource_info['entries']:
                    key_health = "health.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_')) # Use filesystem name instead filesystem id on zabbix key
                    key_sizeUsedBytes = "sizeUsedBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
                    key_sizeTotalBytes = "sizeTotalBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
                    key_sizeAllocatedBytes = "sizeAllocated.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))

                    state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
                    state_resources.append("%s %s %s %s" % (storage_name, key_sizeUsedBytes, timestampnow, one_object['content']['sizeUsed']))
                    state_resources.append("%s %s %s %s" % (storage_name, key_sizeTotalBytes, timestampnow, one_object['content']['sizeTotal']))
                    state_resources.append("%s %s %s %s" % (storage_name, key_sizeAllocatedBytes, timestampnow, one_object['content']['sizeAllocated']))
            else:
                for one_object in resource_info['entries']:
                    # Get state of resources from description
                    descriptionIds = str(one_object['content']['health']['descriptionIds'][0]) # Convert description to string
                    if descriptionIds.find("ALRT_COMPONENT_OK") >= 0:
                        running_status = 8
                    elif descriptionIds.find("ALRT_DISK_SLOT_EMPTY") >= 0:
                        running_status = 6
                    elif descriptionIds.find("ALRT_SLIC_EMPTY") >= 0:
                        running_status = 6
                    else:
                        running_status = 5

                    key_health = "health.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
                    key_status = "running.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
                    state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
                    state_resources.append("%s %s %s %s" % (storage_name, key_status, timestampnow, running_status))
    except Exception as oops:
        unity_logger.error("{0} Error occured in get state".format(api_ip))
        sys.exit("1000")

    api_session_logout = api_logout(api_ip, api_session)
    return send_data_to_zabbix(state_resources, storage_name)

def main():
    # Parsing arguments
    unity_parser = argparse.ArgumentParser()
    unity_parser.add_argument('--api-ip', action="store", help="Where to connect", required=True)
    unity_parser.add_argument('--api-port', action="store", required=True)
    unity_parser.add_argument('--api-user', action="store", required=True)
    unity_parser.add_argument('--api-password', action="store", required=True)
    unity_parser.add_argument('--storage-name', action="store", required=True)

    group = unity_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--discovery', action='store_true')
    group.add_argument('--status', action='store_true')
    arguments = unity_parser.parse_args()

    list_resources = ['battery', 'ssd', 'ethernetPort', 'fcPort', 'sasPort', 'fan', 'powerSupply', 'storageProcessor', 'lun', 'pool', 'dae', 'dpe', 'ioModule', 'lcc', 'memoryModule', 'ssc', 'uncommittedPort', 'disk']
    if arguments.discovery:
        result_discovery = discovering_resources(arguments.api_user, arguments.api_password, arguments.api_ip, arguments.api_port, arguments.storage_name, list_resources)
        print(result_discovery)
    elif arguments.status:
        result_status = get_status_resources(arguments.api_user, arguments.api_password, arguments.api_ip, arguments.api_port, arguments.storage_name, list_resources)
        print(result_status)

if __name__ == "__main__":
    main()