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
    
    debug = 1

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
    packet_mode_json = {
        "name" : "HubLab Network",
        "filter" : "src:146.18.2.137 AND dst:204.135.16.50 AND svc:443",
        "filter-settings" : {
            "search-mode" : "packet"
        }
    }
    
    print(packet_mode_json)

    packet_result = apifunctions.api_call(ip_addr, "show-access-rulebase", packet_mode_json,sid)

    print(json.dumps(packet_result))
    # don't need to publish
    time.sleep(20)

    ### logout
    logout_result = apifunctions.api_call(ip_addr, "logout", {}, sid)
    if(debug == 1):
        print(logout_result)
#endof main()