#!/usr/bin/python3 -W ignore::DeprecationWarning

import requests
import json
import sys
import time
import apifunctions
import cgi,cgitb

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
    print("In Function get_object_dictionary() <br>")
    # Object Dictionary Start
    odebug = 0
    object_dic = {}

    if(odebug == 1):
        print(json.dumps(result_json))
        print("******* OBJ DIC *******<br>")
        print(result_json['objects-dictionary'])

    objdic_size = len(result_json['objects-dictionary'])
    #print(objdic_size)
    for j in range(objdic_size):
        if(odebug == 1):
            print(result_json['objects-dictionary'][j]['name'])
            print("<br>")
            print(result_json['objects-dictionary'][j]['uid'])
            print("<br>")
        object_dic[result_json['objects-dictionary'][j]['uid']] = result_json['objects-dictionary'][j]['name']
    if(odebug == 1):
        print("******* OBJ DIC *******<br>")
        print(object_dic)
        print("*************************************************<br><br>")
    #Object Dictionalry End
    return(object_dic)
#end of get_object_dictionary

"""
parse an access rule (not in a section)
todo : inline testing
"""
def parse_access_rule(result_json, packet_mode_json, ip_addr,sid, inline=False):
    print("In Function parse_acess_rule () <br>")

    total = result_json['total'] ## total number of rules to extract
    ## don't need to track outer looping since depth is 1

    object_d = get_object_dictionary(result_json)

    for i in range(total):
        print("Rule Number : " + str(result_json['rulebase'][i]['rule-number']))
        print("Sources :<br>")
        for x in result_json['rulebase'][i]['source']:
            if(inline == True):
                print("<blockquote>" + object_d[x] + "</blockquote>")
                #print("<br>")
            else:
                print(object_d[x])
                print("<br>")
        #print(result_json['rulebase'][i]['source'])
        print("Destinations :<br>")
        for x in result_json['rulebase'][i]['destination']:
            if(inline == True):
                print("<blockquote>" + object_d[x] + "</blockquote>")
                #print("<br>")
            else:
                print(object_d[x])
                print("<br>")
        #print(result_json['rulebase'][i]['destination'])
        print("Services :<br>")
        for x in result_json['rulebase'][i]['service']:
            if(inline == True):
                print("<blockquote>" + object_d[x] + "</blockquote>")
                #print("<br>")
            else:
                print(object_d[x])
                print("<br>")
        #print(result_json['rulebase'][i]['service'])
        try:
            #not a big fan of the var scope
            inline_uid = result_json['rulebase'][i]['inline-layer'] 
            print(result_json['rulebase'][i]['inline-layer'])
            print("<br>")
            print("@@@@@@@@@@@@@@@@ Start Inline Rule @@@@@@@@@@@@@@@@<br>")
            print("@@@@@@@@@@@@@@@@  End Inline Rule  @@@@@@@@@@@@@@@@<br>")
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
    print("In Function parse_access_section() <br>")

    total = result_json['total'] ## total number we need to extract
    outer_index = 0  #track 'rulebase'[outer_index] to keep up with section
    i = 0  # while loop indexer 

    object_d = get_object_dictionary(result_json)

    length_of_rulebase = len(result_json['rulebase'][outer_index]['rulebase'])
    print("going into loop<br>")

    while(i < total):
        #loop through all the results

        for rule in range(length_of_rulebase):
            if(inline == True):
                print("<blockquote>Rule Number : " + str(result_json['rulebase'][outer_index]['rulebase'][rule]['rule-number']) + "</blockquote>")
                #print("<br>")
            else:
                print("Rule Number : " + str(result_json['rulebase'][outer_index]['rulebase'][rule]['rule-number']))
                print("<br>")
            if(inline == True):
                print("<blockquote>Sources : </blockquote>")
            else:
                print("Sources :<br>")
            for x in result_json['rulebase'][outer_index]['rulebase'][rule]['source']:
                if(inline == True):
                    print("<blockquote>" + object_d[x] + "</blockquote>")
                    #print("<br>")
                else:
                    print(object_d[x])
                    print("<br>")
            #print(result_json['rulebase'][outer_index]['rulebase'][rule]['source'])
            if(inline == True):
                print("<blockquote>Destinations :</blockquote>")
            else:
                print("Destinations :<br>")
            for x in result_json['rulebase'][outer_index]['rulebase'][rule]['destination']:
                if(inline == True):
                    print("<blockquote>" + object_d[x] + "</blockquote>")
                    #print("<br>")
                else:
                    print(object_d[x])
                    #print("<br>")
            #print(result_json['rulebase'][outer_index]['rulebase'][rule]['destination'])
            if(inline == True):
                print("<blockquote>Services :</blockquote>")
            else:
                print("Services :<br>")
            for x in result_json['rulebase'][outer_index]['rulebase'][rule]['service']:
                if(inline == True):
                    print("<blockquote>" + object_d[x] + "</blockquote>")
                    #print("<br>")
                else:
                    print(object_d[x])
                    print("<br>")
            #print(result_json['rulebase'][outer_index]['rulebase'][rule]['service'])
            try:
                #not a big fan of the var scope
                inline_uid = result_json['rulebase'][outer_index]['rulebase'][rule]['inline-layer'] 
                print(result_json['rulebase'][outer_index]['rulebase'][rule]['inline-layer'])
                print("<br>")
                print("@@@@@@@@@@@@@@@@ Start Inline Rule @@@@@@@@@@@@@@@@<br>")
                tmp_json = packet_mode_json
                del tmp_json['name']
                tmp_json.update({'uid' : inline_uid})
                print(tmp_json)
                print("<br>")
                get_rulebase(ip_addr, tmp_json, sid, True)
                print("@@@@@@@@@@@@@@@@  End Inline Rule  @@@@@@@@@@@@@@@@<br>")
            except:
                pass
            print("------------------------------------------------------------------<br><br>")
            i = i + 1
            
        outer_index = outer_index +  1
        if(i < total):
            length_of_rulebase = len(result_json['rulebase'][outer_index]['rulebase'])
    print("out of loop<br>") 
#end of function

def get_rulebase(ip_addr, search_json, sid, inline=False):
    print("In Function get_rulebase <br>")
    packet_result = apifunctions.api_call(ip_addr, "show-access-rulebase", search_json, sid)

    total = packet_result['total'] ## total number we need to extract
    print("Total to search for : " + str(total))
    print("<br>")
    if(total >= 1):
        print("Start of Get_Rulebase<br>")
        print("Result of Total<br>")
        print(total)
        print("<br>")

        print(packet_result['rulebase'][0]['type']) #access-section or access-rule
        print("<br>")

        if(packet_result['rulebase'][0]['type'] == "access-section"):
            parse_access_section(packet_result,search_json,ip_addr,sid,inline)
        
        if(packet_result['rulebase'][0]['type'] == "access-rule"):
            parse_access_rule(packet_result,search_json,ip_addr,sid,inline)

    else:
        print("no rules found<br>")
#end of get_rulebase()

def main():
    debug = 1

    #create instance of Field Storage
    form = cgi.FieldStorage()
    cma = form.getvalue('cma')

    if(cma == "192.168.159.155"):
        policy = form.getvalue('adm5policy')
    elif(cma == "192.168.159.151"):
        policy = form.getvalue('adm1policy')
    elif(cma == "192.168.159.161"):
        policy = form.getvalue('adm11policy')
    elif(cma == "192.168.159.167"):
        policy = form.getvalue('adm17policy')
    else:
        policy = "none"

    #policy5 = form.getvalue('adm5policy')

    source = form.getvalue('sourceip')
    dest = form.getvalue('destip')
    port = form.getvalue('service')

    ## html header and config data dump
    print ("Content-type:text/html\r\n\r\n")
    print ("<html>")
    print ("<head>")
    print ("<title>Packet Mode</title>")
    print ("</head>")
    print ("<body>")
    print ("<br><br>")
    print("Packet Mode 0.1<br><br>")

    print("Values :")
    print(cma)
    print("<br>")
    print(policy)
    print("<br>")
    print(source)
    print("<br>")
    print(dest)
    print("<br>")
    print(port)
    print("<br>")

    packet_mode_json = {
        "name" : policy,
        "filter" : "src:" + source + " AND dst:" + dest + " AND svc:" + port,
        "filter-settings" : {
            "search-mode" : "packet"
        }
    }

    print(packet_mode_json)
    print("<br>")

    ip_addr  = "192.168.159.150"
    ip_cma   = cma
    user     = "roapi"
    password = "1qazxsw2"

    if(cma == "--All--" or policy == "none" or policy == "0"):
        print("you didn't select a cma or a policy")
        print("------- end of program -------")
        print("<br><br>")
        print("</body>")
        print("</html>")
        exit(1)

    sid = apifunctions.login(user,password, ip_addr, ip_cma)

    if(debug == 1):
        print("session id : " + sid)
        print("<br>")

    get_rulebase(ip_addr, packet_mode_json, sid)

    # don't need to publish
    time.sleep(20)

    ### logout
    logout_result = apifunctions.api_call(ip_addr, "logout", {}, sid)
    if(debug == 1):
        print(logout_result)
        print("<br>")

    print("------- end of program -------")
    print("<br><br>")
    print("</body>")
    print("</html>")
#end of main()

if __name__ == "__main__":
    main()