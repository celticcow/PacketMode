#!/usr/bin/python3 -W ignore::DeprecationWarning

import requests
import json
import sys
import time
import argparse
import apifunctions

#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
test code to play around with getting policies from cma

works and moved to function in psearch.py code tree
"""

if __name__ == "__main__":
    
    debug = 1

    if(debug == 1):
        print("policy get  : version 0.1")
    
    parser = argparse.ArgumentParser(description='Policy Extractor')
    parser.add_argument("-m", required=True, help="MDS IP")
    parser.add_argument("-c", required=True, help="CMA IP")

    args = parser.parse_args()

    ip_addr  = args.m
    ip_cma   = args.c
    user     = "roapi"
    password = "1qazxsw2"

    sid = apifunctions.login(user,password, ip_addr, ip_cma)

    if(debug == 1):
        print("session id : " + sid)

    get_package_result = apifunctions.api_call(ip_addr,"show-packages", {"details-level" : "full"}, sid)

    policy_select = {}
    policy_index = 0 # things should start 0

    for i in range(get_package_result['total']):
        size_of_package = len(get_package_result['packages'][i]['access-layers'])
        for j in range(size_of_package):
            current_name = get_package_result['packages'][i]['access-layers'][j]['name']
            if((current_name == "FDX_Services Security") or ("Application" in current_name) or (current_name == "Network")):
                pass
            else:
                #print(current_name)
                policy_select[policy_index] = current_name
                policy_index = policy_index + 1
        #print(get_package_result['packages'][i]['access-layers'][1]['name'])
        #print(get_package_result['packages'][i]['access-layers'][2]['name'])

    print(policy_select)
    #print(json.dumps(get_package_result))
    # don't need to publish
    time.sleep(20)

    ### logout
    logout_result = apifunctions.api_call(ip_addr, "logout", {}, sid)
    if(debug == 1):
        print(logout_result)
#endof main()