#!/usr/bin/python3 -W ignore::DeprecationWarning

import requests
import json
import sys
import time
import apifunctions

#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
gregory.dunlap / celtic_cow

"""
if __name__ == "__main__":
    
    debug = 0

    if(debug == 1):
        print("packet mode search  : version 0.1")

    ip_addr  = "146.18.96.16"
    ip_cma   = "146.18.96.25"
    user     = "roapi"
    password = "1qazxsw2"

    sid = apifunctions.login(user,password, ip_addr, ip_cma)

    if(debug == 1):
        print("session id : " + sid)

    """
    mgmt_cli -r true -d 146.18.96.25 show access-rulebase name "HubLab Network" filter 
    "src:146.18.2.137 AND dst:204.135.16.50 AND svc:443" filter-settings.search-mode packet

    and does not equil AND   the all cap's matter a LOT
    """

    object_dic = {}

    packet_mode_json = {
        "name" : "HubLab Network",
        "filter" : "src:146.18.2.137 AND dst:204.135.16.50 AND svc:443",
        "filter-settings" : {
            "search-mode" : "packet"
        }
    }
    
    print(packet_mode_json)

    packet_result = apifunctions.api_call(ip_addr, "show-access-rulebase", packet_mode_json,sid)

    if(packet_result['total'] >= 1):

        if(debug == 1):
            print(json.dumps(packet_result))

            print("******* OBJ DIC *******")
            print(packet_result['objects-dictionary'])

        objdic_size = len(packet_result['objects-dictionary'])
        #print(objdic_size)
        for j in range(objdic_size):
            if(debug == 1):
                print(packet_result['objects-dictionary'][j]['name'])
                print(packet_result['objects-dictionary'][j]['uid'])
            object_dic[packet_result['objects-dictionary'][j]['uid']] = packet_result['objects-dictionary'][j]['name']
        if(debug == 1):
            print("******* OBJ DIC *******")

            print(object_dic)

            print("*************************************************")

        for i in range(packet_result['total']):
            if(debug == 1):
                print(packet_result['rulebase'][i])
                print("^^^^^^^^^")
            print("rule number: " + str(packet_result['rulebase'][i]['rule-number']))
            #print(packet_result['rulebase'][i]['source'])
            #print(packet_result['rulebase'][i]['destination'])
            #print(packet_result['rulebase'][i]['service'])
            print("Source:")
            for x in packet_result['rulebase'][i]['source']:
                print(object_dic[x])
            print("Destination:")
            for x in packet_result['rulebase'][i]['destination']:
                print(object_dic[x])
            print("Service:")
            for x in packet_result['rulebase'][i]['service']:
                print(object_dic[x])
            print("-------------------------------------------------------")
    else:
        print("No rule found")
    
    # don't need to publish
    time.sleep(20)

    ### logout
    logout_result = apifunctions.api_call(ip_addr, "logout", {}, sid)
    if(debug == 1):
        print(logout_result)
#endof main()