#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jan  8 23:38:57 2023

@author: didik
"""

from scapy.all import *
import itertools
import numpy as np
import csv
import random
import socket
import struct


def forward(line):
    try:
        tuple5 = list()
        tuple5.append(line[4])
        tuple5.append(line[6])
        tuple5.append(line[3].upper())
        if(line[5] != ''):
            tuple5.append(int(line[5]))
        else:
            tuple5.append('')
        if(line[7] != ''):
            tuple5.append(int(line[7]))
        else:
            tuple5.append('')
    except ValueError:
        pass
    return tuple5

def retreat(line):
    try:
        tuple5 = list()
        tuple5.append(line[6])
        tuple5.append(line[4])
        tuple5.append(line[3].upper())
        if(line[7] != ''):
            tuple5.append(int(line[7]))
        else:
            tuple5.append('')
        if(line[5] != ''):
            tuple5.append(int(line[5]))
        else:
            tuple5.append('')
    except ValueError:
        pass
    return tuple5

def sortappend(a,b):
    L=PacketList() 
    while True:
        if len(a) == 0 : 
            L = L + b 
            break 
        elif len(b) == 0: 
            L = L + a 
            break 
        if a[0].time < b[0].time: 
            L = L + a[:1] 
            a=a[1:] 
        elif a[0].time > b[0].time: 
            L = L + b[:1] 
            b=b[1:] 
        else: 
            L = L + a[:1] 
            L = L + b[:1] 
            a=a[1:] 
            b=b[1:]
    return PacketList(L)

def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
        )


if __name__ == "__main__":

    attacks = ['mirai', 'disk_wipe', 'ransomware', 'resource_hijacking', 'end_point_dos']
    states = ['normal', 'abnormal']
    splits = ['train', 'test']
    timestamps_start = [1603252045, 1605167757.309540, 1604827364.977316, 1605170191.591887, 1605706691.479608]
    timestamps_end = [1603252842, 1605167869.705448, 1604827526.346817, 1605170345.245436, 1605706900.162720]
    host_address = {'mirai':['192.168.1.111', '192.168.1.11'], 'disk_wipe':['192.168.1.11'], 
                    'ransomware':['192.168.1.11'], 'resource_hijacking':['192.168.1.11'],
                    'end_point_dos':['192.168.1.11']}  
    for attack in attacks:

        # =============================================================================
        # label_traffic flow
        # ============================================================================= 
        reader = csv.reader(open('../datasets/raw_datasets/CREMEv1/label_traffic_'+ attack +'.csv', newline=''))
        title = next(reader)
        lines = list(reader)
        normal_flow = list()
        abnormal_flow = list()
 	    for line in lines:
		#normal flow
		if(line[26] == '0':
		    normal_flow.append(forward(line))
		    normal_flow.append(retreat(line))
		    
		#abnormal flow
		elif(line[26] != '0':
		    abnormal_flow.append(forward(line))
		    abnormal_flow.append(retreat(line))
	    print(len(abnormal_flow))
    
        
    
        # =============================================================================
        # generate normal/abnormal pcap
        # =============================================================================
        # attack = 'mirai'
        print(attack)
        pkts = rdpcap('../datasets/raw_datasets/CREMEv1/Raw_data/traffic_' + attack + '.pcap')
        
        normal_pcap = []
        abnormal_pcap = []
        for pkt in pkts:
            if(pkt.time > timestamps_start[attacks.index(attack)] and pkt.time < timestamps_end[attacks.index(attack)]):
                tuple5 = list()
                if(pkt.payload.name == 'ARP' and (pkt.payload.psrc in host_address[attack] or pkt.payload.pdst in host_address[attack])):
                    #pkt.display()
                    try:
                        tuple5.append(pkt.payload.psrc)
                        tuple5.append(pkt.payload.pdst)
                        tuple5.append(pkt.payload.name)
                        tuple5.append('')
                        tuple5.append('')
                    except ValueError:
                        print('verror')
                        pass
                    except AttributeError:
                        print('aerror')
                        pass
                elif(pkt.payload.name == 'IP' and (pkt.payload.src in host_address[attack] or pkt.payload.dst in host_address[attack])):
                    try:
                        tuple5.append(pkt.payload.src)
                        tuple5.append(pkt.payload.dst)
                        tuple5.append(pkt.payload.payload.name)
                        if(pkt.payload.payload.name =="ICMP"):
                            continue
                        else:
                            tuple5.append(pkt.payload.payload.sport)
                            tuple5.append(pkt.payload.payload.dport)
                    except ValueError:
                        print('verror')
                        pass
                    except AttributeError:
                        print('aerror')
                        pass
                if(tuple5 in normal_flow):
                    normal_pcap.append(pkt)
                elif(tuple5 in abnormal_flow):
                    abnormal_pcap.append(pkt)
    
            
        wrpcap("../datasets/split_benign_attack/cremev1/normal_" + attack + ".pcap", normal_pcap)
        wrpcap("../datasets/split_benign_attack/cremev1/abnormal_" + attack + ".pcap", abnormal_pcap)
    
