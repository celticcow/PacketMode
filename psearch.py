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

"""
takes json from show access-rulebase and extracts the object dictionary
and returns this as a python dic 
"""
def get_object_dictionary(result_json):
    print("In Function get_object_dictionary() ")
    # Object Dictionary Start
    odebug = 0
    object_dic = {}

    if(odebug == 1):
        print(json.dumps(result_json))
        print("******* OBJ DIC *******")
        print(result_json['objects-dictionary'])

    objdic_size = len(result_json['objects-dictionary'])
    #print(objdic_size)
    for j in range(objdic_size):
        if(odebug == 1):
            print(result_json['objects-dictionary'][j]['name'])
            print(result_json['objects-dictionary'][j]['uid'])
        object_dic[result_json['objects-dictionary'][j]['uid']] = result_json['objects-dictionary'][j]['name']
    if(odebug == 1):
        print("******* OBJ DIC *******")
        print(object_dic)
        print("*************************************************")
    #Object Dictionalry End
    return(object_dic)
#end of get_object_dictionary

"""
parse an access rule (not in a section)
todo : inline testing
"""
def parse_access_rule(result_json, packet_mode_json, ip_addr,sid, inline=False):
    print("In Function parse_acess_rule () ")

    total = result_json['total'] ## total number of rules to extract
    ## don't need to track outer looping since depth is 1

    object_d = get_object_dictionary(result_json)

    for i in range(total):
        print("Rule Number : " + str(result_json['rulebase'][i]['rule-number']))
        print("Sources :")
        for x in result_json['rulebase'][i]['source']:
            if(inline == True):
                print("\t" + object_d[x])
            else:
                print(object_d[x])
        #print(result_json['rulebase'][i]['source'])
        print("Destinations :")
        for x in result_json['rulebase'][i]['destination']:
            if(inline == True):
                print("\t" + object_d[x])
            else:
                print(object_d[x])
        #print(result_json['rulebase'][i]['destination'])
        print("Services :")
        for x in result_json['rulebase'][i]['service']:
            if(inline == True):
                print("\t" + object_d[x])
            else:
                print(object_d[x])
        #print(result_json['rulebase'][i]['service'])
        try:
            #not a big fan of the var scope
            inline_uid = result_json['rulebase'][i]['inline-layer'] 
            print(result_json['rulebase'][i]['inline-layer'])
            print("@@@@@@@@@@@@@@@@ Start Inline Rule @@@@@@@@@@@@@@@@")
            print("@@@@@@@@@@@@@@@@  End Inline Rule  @@@@@@@@@@@@@@@@")
        except:
            pass

        print("------------------------------------------------------------------")
    #end of for loop
#end of parse_access_rule()

"""
parse an access section 
tested with regular
todo : inline layer testing
"""
def parse_access_section(result_json, packet_mode_json, ip_addr, sid, inline=False):
    print("In Function parse_access_section() ")

    total = result_json['total'] ## total number we need to extract
    outer_index = 0  #track 'rulebase'[outer_index] to keep up with section
    i = 0  # while loop indexer 

    object_d = get_object_dictionary(result_json)

    length_of_rulebase = len(result_json['rulebase'][outer_index]['rulebase'])
    print("going into loop")

    while(i < total):
        #loop through all the results

        for rule in range(length_of_rulebase):
            if(inline == True):
                print("\tRule Number : " + str(result_json['rulebase'][outer_index]['rulebase'][rule]['rule-number']))
            else:
                print("Rule Number : " + str(result_json['rulebase'][outer_index]['rulebase'][rule]['rule-number']))
            if(inline == True):
                print("\tSources :")
            else:
                print("Sources :")
            for x in result_json['rulebase'][outer_index]['rulebase'][rule]['source']:
                if(inline == True):
                    print("\t" + object_d[x])
                else:
                    print(object_d[x])
            #print(result_json['rulebase'][outer_index]['rulebase'][rule]['source'])
            if(inline == True):
                print("\tDestinations :")
            else:
                print("Destinations :")
            for x in result_json['rulebase'][outer_index]['rulebase'][rule]['destination']:
                if(inline == True):
                    print("\t" + object_d[x])
                else:
                    print(object_d[x])
            #print(result_json['rulebase'][outer_index]['rulebase'][rule]['destination'])
            if(inline == True):
                print("\tServices :")
            else:
                print("Services :")
            for x in result_json['rulebase'][outer_index]['rulebase'][rule]['service']:
                if(inline == True):
                    print("\t" + object_d[x])
                else:
                    print(object_d[x])
            #print(result_json['rulebase'][outer_index]['rulebase'][rule]['service'])
            try:
                #not a big fan of the var scope
                inline_uid = result_json['rulebase'][outer_index]['rulebase'][rule]['inline-layer'] 
                print(result_json['rulebase'][outer_index]['rulebase'][rule]['inline-layer'])
                print("@@@@@@@@@@@@@@@@ Start Inline Rule @@@@@@@@@@@@@@@@")
                tmp_json = packet_mode_json
                del tmp_json['name']
                tmp_json.update({'uid' : inline_uid})
                print(tmp_json)
                get_rulebase(ip_addr, tmp_json, sid, True)
                print("@@@@@@@@@@@@@@@@  End Inline Rule  @@@@@@@@@@@@@@@@")
            except:
                pass
            print("------------------------------------------------------------------")
            i = i + 1
            
        outer_index = outer_index +  1
        if(i < total):
            length_of_rulebase = len(result_json['rulebase'][outer_index]['rulebase'])
    print("out of loop") 
#end of function

def get_rulebase(ip_addr, search_json, sid, inline=False):
    print("In Function get_rulebase ")
    packet_result = apifunctions.api_call(ip_addr, "show-access-rulebase", search_json, sid)

    total = packet_result['total'] ## total number we need to extract
    print("Total to search for : " + str(total))
    if(total >= 1):
        print("Start of Get_Rulebase")
        print("Result of Total")
        print(total)

        print(packet_result['rulebase'][0]['type']) #access-section or access-rule

        if(packet_result['rulebase'][0]['type'] == "access-section"):
            parse_access_section(packet_result,search_json,ip_addr,sid,inline)
        
        if(packet_result['rulebase'][0]['type'] == "access-rule"):
            parse_access_rule(packet_result,search_json,ip_addr,sid,inline)

    else:
        print("no rules found")
#end of get_rulebase()

"""
major bugs with access-section
code ugly and hard to read and track too

split into different functions above

def get_rules(ip_addr, search_json, sid, inline=False):
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

        # Object Dictionary Start
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
        #Object Dictionalry End

        if(depth == "access-section"):
            print("&&&&& Debug of Access Section &&&&&")
            print(packet_result['rulebase'])
            seclen = len(packet_result['rulebase'])
            for k in range(seclen):
                print(k)
                print(packet_result['rulebase'][k])
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")

        for i in range(packet_result['total']):
            if(debug == 1):
                print(packet_result['total'])
            if(debug == 1):
                #print(packet_result['rulebase'][i]['rulebase'])
                print(i)
                #print(packet_result['rulebase'][i]['rulebase'][0]['rule-number'])
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
                    print("=-=-=-=-=-=-=-=-=")
                    try:
                        print("rule number: " + str(packet_result['rulebase'][i]['rulebase'][0]['rule-number']))
                        tmplen = len(packet_result['rulebase'][i]['rulebase'])
                        print("Lenght of rulebase i rulebase " + str(tmplen))
                        print("dump of rulebase i rulebase 0")
                        print(packet_result['rulebase'][i]['rulebase'][0])
                    except:
                        print("Except")
                        print(i)
                        tmplen = len(packet_result['rulebase'])
                        print("length of rulebase " + str(tmplen))
                        print(packet_result['rulebase'])
                        #print(packet_result['rulebase'][0]['rulebase'][0]['rule-number'])
                        #print(packet_result['rulebase'][1]['rulebase'][0]['rule-number'])
                        print(" end of except ")
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
                if(inline == True):
                    print("\trule number: " + str(packet_result['rulebase'][i]['rule-number']))
                else:
                    print("rule number: " + str(packet_result['rulebase'][i]['rule-number']))
                if(inline == True):
                    print("\tSource:")
                else:
                    print("Source:")
                for x in packet_result['rulebase'][i]['source']:
                    if(inline == True):
                        print("\t" + object_dic[x])
                    else:
                        print(object_dic[x])
                if(inline == True):
                    print("\tDestination:")
                else:
                    print("Destination:")
                for x in packet_result['rulebase'][i]['destination']:
                    if(inline == True):
                        print("\t" + object_dic[x])
                    else:
                        print(object_dic[x])
                if(inline == True):
                    print("\tService:")
                else:
                    print("Service:")
                for x in packet_result['rulebase'][i]['service']:
                    if(inline == True):
                        print("\t" + object_dic[x])
                    else:
                        print(object_dic[x])
                try:
                    #need test case
                    print(packet_result['rulebase'][i]['inline-layer'])
                    print("Inline opp")
                    tmpjson = search_json
                    del tmpjson['name']
                    tmpjson.update({'uid' : packet_result['rulebase'][i]['inline-layer']})
                    print(tmpjson)
                    get_rules(ip_addr,tmpjson,sid,True)
                    print("end inline opp")
                except:
                    pass
            if(depth == "access-section"):
                #print(packet_result['rulebase'][i]['rulebase'][0]['inline-layer'])
                if(inline == True):
                    print("\trule number: " + str(packet_result['rulebase'][i]['rulebase'][0]['rule-number']))
                else:
                    print("rule number: " + str(packet_result['rulebase'][i]['rulebase'][0]['rule-number']))
                if(inline == True):
                    print("\tSource:")
                else:
                    print("Source:")
                for x in packet_result['rulebase'][i]['rulebase'][0]['source']:
                    if(inline == True):
                        print("\t" + object_dic[x])
                    else:
                        print(object_dic[x])
                if(inline == True):
                    print("\tDestination:")
                else:
                    print("Destination:")
                for x in packet_result['rulebase'][i]['rulebase'][0]['destination']:
                    if(inline == True):
                        print("\t" + object_dic[x])
                    else:
                        print(object_dic[x])
                if(inline == True):
                    print("\tService:")
                else:
                    print("Service:")
                for x in packet_result['rulebase'][i]['rulebase'][0]['service']:
                    if(inline == True):
                        print("\t" + object_dic[x])
                    else:
                        print(object_dic[x])
                try:
                    print(packet_result['rulebase'][i]['rulebase'][0]['inline-layer'])
                    print("Start Inline Rule")
                    tmpjson = search_json
                    del tmpjson['name']
                    tmpjson.update({'uid' : packet_result['rulebase'][i]['rulebase'][0]['inline-layer']})
                    print(tmpjson)
                    get_rules(ip_addr,tmpjson,sid,True)
                    print("End Inline Rule")
                except:
                    pass
            
            print("-------------------------------------------------------")
    else:
        print("No rule found")
"""
def main():
    
    debug = 1

    if(debug == 1):
        print("packet mode search  : version 0.3")

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

    #packet_mode_json = {
    #    "name" : "SearchTest Network",
    #    "filter" : "src:146.18.2.137 AND dst:10.250.1.1 AND svc:443",
    #    "filter-settings" : {
    #        "search-mode" : "packet"
    #    }
    #}
    
    #object_dic   = {}
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

    get_rulebase(ip_addr, packet_mode_json, sid)

    #get_rules(ip_addr, packet_mode_json, sid)
    
    # don't need to publish
    time.sleep(20)

    ### logout
    logout_result = apifunctions.api_call(ip_addr, "logout", {}, sid)
    if(debug == 1):
        print(logout_result)
#endof main()

if __name__ == "__main__":
    main()