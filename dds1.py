#!/usr/bin/env python
import requests
import json
import os
import re
ifindexToDpid = {'s1':1,'s2':2,'s3':3,'s4':4,'s5':5,'s6':6,'s7':7,'s8':8,'s9':9,'s10':10}
ifindexToPort = {}
nameToPort = {}
path = '/sys/devices/virtual/net/'
for child in os.listdir(path):
    parts = re.match('(.*)-(.*)', child)
    if parts == None: continue
    ifindex = open(path+child+'/ifindex').read().split('\n',1)[0]
    ifindexToPort[ifindex] = {'switch':parts.group(1),'port':child}
    ifindexToPort[str(int(ifindex))] = ifindexToPort[ifindex]
    nameToPort[child] = ifindexToPort[ifindex]
#print json.dumps(ifindexToPort) 

groups = {'external':['0.0.0.0/0'],'internal':['10.0.0.0/29']}
target = 'http://localhost:8008'
r = requests.put(target + '/group/groupddos/json',data=json.dumps(groups))

flows = {'keys':'inputifindex,ipsource,ipdestination','value':'bytes','filter':'group:ipsource:groupddos=external&group:ipdestination:groupddos=internal','log':True}

r = requests.put(target + '/flow/incoming/json',data=json.dumps(flows))
threshold = {'metric':'incoming','value':1000000/3}

r = requests.put(target + '/threshold/incoming/json',data=json.dumps(threshold))

eventurl = target + '/events/json?maxEvents=10&timeout=60'
eventID = -1
while 1 == 1:
    r = requests.get(eventurl + '&eventID=' + str(eventID))
    if r.status_code != 200: break
    events = r.json()
    if len(events) == 0: continue
    eventID = events[0]["eventID"]
    for e in events:
        if 'incoming' == e['metric']:
            r = requests.get(target + '/metric/' + e['agent'] + '/' + e['dataSource'] + '.' + e['metric'] + '/json')
            metric = r.json()
            if len(metric) > 0:
		result_arr = metric[0]['topKeys'][0]['key'].split(',')
		snmp_index = str(result_arr[0])
		src_ip = str(result_arr[1])
		dst_ip = str(result_arr[2])
		#print src_ip
		#print dst_ip
		#src_ip = "10.0.0.132"
		#dst_ip = "10.0.0.2"
		switch_name = ifindexToPort[snmp_index]["switch"]
		switch_port = ifindexToPort[snmp_index]["port"]
		switch_dpid = ifindexToDpid[switch_name]
		flow_entry = {"dpid":switch_dpid,"cookie":1,"cookie_mask":1,"table_id":0,"priority":65000,'hard_timeout':60,"flags":1,"match":{"eth_type":2048,"ipv4_src":src_ip,"eth_type":2048,"ipv4_dst":dst_ip},"actions":[{"type":'CLEAR_ACTIONS'}]}	
		requests.post('http://192.168.56.102:8080/stats/flowentry/add',data=json.dumps(flow_entry))
		print switch_dpid
		print switch_port
                print metric[0]['topKeys'][0]['key']
		#print requests.get(target+'/agents/json').content
		#print requests.get(target+'/metric/127.0.0.1/669.of_dpid/json').content
