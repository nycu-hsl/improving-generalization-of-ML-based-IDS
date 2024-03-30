#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 26 00:55:08 2023

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
    tuple5 = list()
    tuple5.append(line[1])
    tuple5.append(line[3])
    tuple5.append(line[5].upper())
    if(line[2] != ''):
        tuple5.append(int(line[2]))
    else:
        tuple5.append('')
    if(line[4] != ''):
        tuple5.append(int(line[4]))
    else:
        tuple5.append('')
    return tuple5

def retreat(line):
    tuple5 = list()
    tuple5.append(line[3])
    tuple5.append(line[1])
    tuple5.append(line[5].upper())
    if(line[4] != ''):
        tuple5.append(int(line[4]))
    else:
        tuple5.append('')
    if(line[2] != ''):
        tuple5.append(int(line[2]))
    else:
        tuple5.append('')
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

protocol_mapping = {
    6: 'TCP',
    17: 'UDP'
}

if __name__ == "__main__":

    
    attacks = ['botnet', 'ddos', 'infiltration_cool_disk', 'infiltration_dropbox', 'port_scan', 'brute_force_ssh_patator', 'web_attack_brute_force', 'web_attack_sqli', 'web_attack_xss']
    states = ['normal', 'abnormal']
    timestamps_start = [1499433000.000000, 1499453760.000000, 1499363580.000000, 1499364240.000000, 1499446500.000000, 1499187600.000000, 1499343600.000000, 1499348400.000000, 1499346900.000000]
    timestamps_end = [1499436120.000000, 1499454960.000000, 1499364000.000000, 1499366700.000000, 1499448900.000000, 1499191200.000000, 1499346000.000000, 1499348520.000000, 1499348100.000000]
    host_address = {'botnet':['192.168.10.14', '192.168.10.15', '192.168.10.9', '192.168.10.5', '192.168.10.8'],
    'ddos':['192.168.10.50'],
    'infiltration_cool_disk':['192.168.10.25'],
    'infiltration_dropbox':['192.168.10.8'],
    'port_scan':['192.168.10.50'],
    'brute_force_ssh_patator':['192.168.10.50','205.174.165.68'],
    'web_attack_brute_force':['192.168.10.50','205.174.165.68'],
    'web_attack_sqli':['192.168.10.50','205.174.165.68'],
    'web_attack_xss':['192.168.10.50','205.174.165.68']
    }  
    
    
    #%%
    for attack in attacks:
        print(attack)
        # =============================================================================
        # label_traffic flow
        # ============================================================================= 
        reader = csv.reader(open('../datasets/raw_datasets/CICIDS_2017_Generated_Labelled_Flows/' + attack + '.csv', newline=''))
        title = next(reader)
        lines = list(reader)
        normal_flow = list()
        abnormal_flow = list()
        for line in lines:
            #normal flow
            if(line[84] == 'BENIGN'):
                normal_flow.append(forward(line))
                normal_flow.append(retreat(line))
                
            #abnormal flow
            elif(line[84] != 'BENIGN'):
                abnormal_flow.append(forward(line))
                abnormal_flow.append(retreat(line))
        print(len(abnormal_flow))
        
        # Mapping of protocol numbers to their names

        for item in abnormal_flow:
            protocol_number = int(item[2])  # Assuming item[2] contains the protocol number
            # Replace the protocol number with its name if available in the mapping
            item[2] = protocol_mapping.get(protocol_number, 'Unknown')

                
        # =============================================================================
        # generate normal/abnormal pcap
        # =============================================================================

        print(attack)
        pkts = rdpcap('../datasets/raw_datasets/CICIDS_2017/traffic_' + attack + '.pcap')
        
        
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
                        # print('appenddd')
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
                            print('ICMP')
                            pass
                            
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

            
        wrpcap("../datasets/split_benign_attack/cicids2017/normal_" + attack + ".pcap", normal_pcap)
        wrpcap("../datasets/split_benign_attack/cicids2017/abnormal_" + attack + ".pcap", abnormal_pcap)
