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
gregory.dunlap / celtic_cow

"""

def get_policies(ip_addr,sid):
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

    print(policy_select)
    return(policy_select)
#end of get_policies

def get_rules(ip_addr, search_json, sid):
    print("-=-=-= In get_rules() =-=-=-")
    object_dic   = {}

    packet_result = apifunctions.api_call(ip_addr, "show-access-rulebase", search_json, sid)

    if(packet_result['total'] >= 1):

        depth = packet_result['rulebase'][0]['type']
        # access-rule
        # access-section
        # need to check inline layers todo
        if(debug == 1):
            print("_________________________")
            print(depth)
            print("_________________________")

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
                print(packet_result['total'])
            if(debug == 1):
                #print(packet_result['rulebase'][i]['rulebase'])
                print("^^^^^^^^^")
            #print("rule number: " + str(packet_result['rulebase'][i]['rulebase'][0]['rule-number']))
            
            if(debug == 1):
                #no global
                if(depth == "access-rule"):
                    print("rule number: " + str(packet_result['rulebase'][i]['rule-number']))
                    print(packet_result['rulebase'][i]['source'])
                    print(packet_result['rulebase'][i]['destination'])
                    print(packet_result['rulebase'][i]['service'])
                    try:
                        print(packet_result['rulebase'][i]['inline-layer'])
                        print("Inline above yo")
                        ## check more
                    except:
                        pass
                #global = yes
                if(depth == "access-section"):
                    print("rule number: " + str(packet_result['rulebase'][i]['rulebase'][0]['rule-number']))
                    print(packet_result['rulebase'][i]['rulebase'][0]['source'])
                    print(packet_result['rulebase'][i]['rulebase'][0]['destination'])
                    print(packet_result['rulebase'][i]['rulebase'][0]['service'])
                    try:
                        print(packet_result['rulebase'][i]['rulebase'][0]['inline-layer'])
                        print("Inline Above Yo")
                    except:
                        pass

            ## need to figure out why extra index ?
            if(depth == "access-rule"):
                print("rule number: " + str(packet_result['rulebase'][i]['rule-number']))
                print("Source:")
                for x in packet_result['rulebase'][i]['source']:
                    print(object_dic[x])
                print("Destination:")
                for x in packet_result['rulebase'][i]['destination']:
                    print(object_dic[x])
                print("Service:")
                for x in packet_result['rulebase'][i]['service']:
                    print(object_dic[x])
                try:
                    #need test case
                    print(packet_result['rulebase'][i]['inline-layer'])
                    print("Inline opp")
                    tmpjson = search_json
                    del tmpjson['name']
                    tmpjson.update({'uid' : packet_result['rulebase'][i]['inline-layer']})
                    print(tmpjson)
                    get_rules(ip_addr,tmpjson,sid)
                    print("end inline opp")
                except:
                    pass
            if(depth == "access-section"):
                #print(packet_result['rulebase'][i]['rulebase'][0]['inline-layer'])
                print("rule number: " + str(packet_result['rulebase'][i]['rulebase'][0]['rule-number']))
                print("Source:")
                for x in packet_result['rulebase'][i]['rulebase'][0]['source']:
                    print(object_dic[x])
                print("Destination:")
                for x in packet_result['rulebase'][i]['rulebase'][0]['destination']:
                    print(object_dic[x])
                print("Service:")
                for x in packet_result['rulebase'][i]['rulebase'][0]['service']:
                    print(object_dic[x])
                try:
                    print(packet_result['rulebase'][i]['rulebase'][0]['inline-layer'])
                    print("Inline opp")
                    tmpjson = search_json
                    del tmpjson['name']
                    tmpjson.update({'uid' : packet_result['rulebase'][i]['rulebase'][0]['inline-layer']})
                    print(tmpjson)
                    get_rules(ip_addr,tmpjson,sid)
                    print("end inline opp")
                except:
                    pass
            
            print("-------------------------------------------------------")
    else:
        print("No rule found")

if __name__ == "__main__":
    
    debug = 0

    if(debug == 1):
        print("packet mode search  : version 0.1")

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

    """
    mgmt_cli -r true -d 146.18.96.25 show access-rulebase name "HubLab Network" filter 
    "src:146.18.2.137 AND dst:204.135.16.50 AND svc:443" filter-settings.search-mode packet

    and does not equil AND   the all cap's matter a LOT
    """

    object_dic   = {}
    policies_dic = {}

    policies_dic = get_policies(ip_addr,sid)

    if(debug == 1):
        print("*****")
        print(policies_dic)
        print("*****")

    for x in policies_dic:
        print(str(x) + " : " + policies_dic[x])

    policy     = input("Select a number above : ")
    source_ip  = input("Enter Source IP : ")
    dest_ip    = input("Enter Dest IP : ")
    dport      = input("Enter Dest Port : ")
    packet_mode_json = {
        "name" : policies_dic[int(policy)],
        "filter" : "src:" + source_ip + " AND dst:" + dest_ip + " AND svc:" + dport,
        "filter-settings" : {
            "search-mode" : "packet"
        }
    }
   
    if(debug == 1):
        print(packet_mode_json)

    get_rules(ip_addr, packet_mode_json, sid)
    
    # don't need to publish
    time.sleep(20)

    ### logout
    logout_result = apifunctions.api_call(ip_addr, "logout", {}, sid)
    if(debug == 1):
        print(logout_result)
#endof main()