#!/usr/bin/python3

import json

"""
garbage script for learning to add and remove elements 
from json so i can make the convert from name to uid
"""

print("start")

tmpjson = {
    "uid" : "e1942eee-7198-4038-a1a7-c9455cb61d71",
    "filter" : "src:10.231.40.5 AND dst:10.230.36.5 AND svc:5201",
    "filter-settings" : {
        "search-mode" : "packet"
    }
}

print(tmpjson)

del tmpjson['uid']

print(tmpjson)

tmpjson.update({'name' : 'policy'})

print(tmpjson)
"""
tmp = dict(tmpjson)
del tmp['uid']

print(tmp)
"""