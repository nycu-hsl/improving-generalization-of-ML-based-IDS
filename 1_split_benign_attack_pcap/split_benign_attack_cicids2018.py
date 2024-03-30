
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 26 01:03:16 2023

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


if __name__ == "__main__": 
    
    attacks = ['22_02_thursday_sql_injection',
               '22_02_thursday_brute_xss',
               '22_02_thursday_brute_web',
               '16_02_friday_dos_slowhttp',
               '14_02_wed_ftp_bruteforce',
               '28_02_wed_infiltration',
               '15_02_thursday_dos_goldeneye',
               '201_03_thursday_infiltration_2',
               '201_03_thursday_infiltration',
               '28_02_wed_infiltration_2',
               '15_02_thursday_dos_slowloris',
               '202_03_friday_botnet_2',
               '202_03_friday_botnet',
               '20_02_tuesday_ddos_loichttp',
               '14_02_wed_ssh_bruteforce',
               '21_02_ddos_hoic',
               '16_02_friday_dos_hulk']
    
    timestamps_start = [1519330500.000000, 1519321800.000000, 1519309020.000000, 1518790320.000000, 1518618720.000000, 
                        1519829400.000000, 1518701160.000000, 1519927200.000000, 1519912620.000000, 1519839720.000000, 
                        1518706740.000000, 1520015040.000000, 1519999860.000000, 1519135920.000000, 1518631260.000000,
                        1519236300.000000, 1518803100.000000]
    timestamps_end = [1519331340.000000, 1519324140.000000, 1519313040.000000, 1518793680.000000, 1518624540.000000,
                      1519833900.000000, 1518703740.000000, 1519933020.000000, 1519927200.000000, 1519843200.000000, 
                      1518709200.000000, 1520020500.000000, 1520004840.000000, 1519139820.000000, 1518636660.000000,
                      1519239900.000000, 1518805140.000000]
    
    host_address = {'22_02_thursday_sql_injection':['172.31.69.28'],
                    '22_02_thursday_brute_xss':['172.31.69.28'],
                    '22_02_thursday_brute_web':['172.31.69.28'],
                    '16_02_friday_dos_slowhttp':['172.31.69.25'],
                    '14_02_wed_ftp_bruteforce':['172.31.69.25'],
                    '28_02_wed_infiltration':['172.31.69.24'],
                    '15_02_thursday_dos_goldeneye':['172.31.69.25'],
                    '201_03_thursday_infiltration_2':['172.31.69.13'],
                    '201_03_thursday_infiltration':['172.31.69.13'],
                    '28_02_wed_infiltration_2':['172.31.69.24'],
                    '15_02_thursday_dos_slowloris':['172.31.69.25'],
                    '202_03_friday_botnet_2':['172.31.69.23','172.31.69.17','172.31.69.14','172.31.69.12','172.31.69.10','172.31.69.8','172.31.69.6','172.31.69.26',
                                              '172.31.69.29','172.31.69.30'],
                    '202_03_friday_botnet':['172.31.69.23','172.31.69.17','172.31.69.14','172.31.69.12','172.31.69.10','172.31.69.8','172.31.69.6','172.31.69.26',
                                              '172.31.69.29','172.31.69.30'],
                    '20_02_tuesday_ddos_loichttp':['172.31.69.25'],
                    '14_02_wed_ssh_bruteforce':['172.31.69.25'],
                    '21_02_ddos_hoic':['172.31.69.28'],
                    '16_02_friday_dos_hulk':['172.31.69.25']}
   
    abnormal_flow = {'22_02_thursday_sql_injection':[['18.218.115.60','172.31.69.28','TCP'],['172.31.69.28','18.218.115.60','TCP']],
                    '22_02_thursday_brute_xss':[['18.218.115.60','172.31.69.28','TCP'],['172.31.69.28','18.218.115.60','TCP']],
                    '22_02_thursday_brute_web':[['18.218.115.60','172.31.69.28','TCP'],['172.31.69.28','18.218.115.60','TCP']],
                    '16_02_friday_dos_slowhttp':[['13.59.126.31','172.31.69.25','TCP'],['172.31.69.25','13.59.126.31','TCP']],
                    '14_02_wed_ftp_bruteforce':[['18.218.115.60','172.31.69.28','TCP'],['172.31.69.28','18.218.115.60','TCP']],
                    '28_02_wed_infiltration':[['13.58.225.34','172.31.69.24','TCP'],['172.31.69.24','13.58.225.34','TCP']],
                    '15_02_thursday_dos_goldeneye':[['18.219.211.138','172.31.69.25','TCP'],['172.31.69.25','18.219.211.138','TCP']],
                    '201_03_thursday_infiltration_2':[['13.58.225.34','172.31.69.13','TCP'],['172.31.69.13','13.58.225.34','TCP']],
                    '201_03_thursday_infiltration':[['13.58.225.34','172.31.69.13','TCP'],['172.31.69.13','13.58.225.34','TCP']],
                    '28_02_wed_infiltration_2':[['13.58.225.34','172.31.69.24','TCP'],['172.31.69.24','13.58.225.34','TCP']],
                    '15_02_thursday_dos_slowloris':[['18.217.165.70','172.31.69.25','TCP'],['172.31.69.25','18.217.165.70','TCP']],
                    '202_03_friday_botnet_2':[['18.219.211.138','172.31.69.23','TCP'],['172.31.69.23','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.17','TCP'],['172.31.69.17','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.14','TCP'],['172.31.69.14','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.12','TCP'],['172.31.69.12','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.10','TCP'],['172.31.69.10','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.8','TCP'],['172.31.69.8','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.6','TCP'],['172.31.69.6','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.26','TCP'],['172.31.69.26','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.29','TCP'],['172.31.69.29','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.30','TCP'],['172.31.69.30','18.219.211.138','TCP'],
                                              ],
                    '202_03_friday_botnet':[['18.219.211.138','172.31.69.23','TCP'],['172.31.69.23','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.17','TCP'],['172.31.69.17','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.14','TCP'],['172.31.69.14','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.12','TCP'],['172.31.69.12','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.10','TCP'],['172.31.69.10','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.8','TCP'],['172.31.69.8','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.6','TCP'],['172.31.69.6','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.26','TCP'],['172.31.69.26','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.29','TCP'],['172.31.69.29','18.219.211.138','TCP'],
                                              ['18.219.211.138','172.31.69.30','TCP'],['172.31.69.30','18.219.211.138','TCP'],
                                              ],
                    '20_02_tuesday_ddos_loichttp':[['18.218.115.60','172.31.69.25','TCP'],['172.31.69.25','18.218.115.60','TCP'],
                                                   ['18.219.9.1','172.31.69.25','TCP'],['172.31.69.25','18.219.9.1','TCP'],
                                                   ['18.219.32.43','172.31.69.25','TCP'],['172.31.69.25','18.219.32.43','TCP'],
                                                   ['18.218.55.126','172.31.69.25','TCP'],['172.31.69.25','18.218.55.126','TCP'],
                                                   ['52.14.136.135','172.31.69.25','TCP'],['172.31.69.25','52.14.136.135','TCP'],
                                                   ['18.219.5.43','172.31.69.25','TCP'],['172.31.69.25','18.219.5.43','TCP'],
                                                   ['18.216.200.189','172.31.69.25','TCP'],['172.31.69.25','18.216.200.189','TCP'],
                                                   ['18.218.229.235','172.31.69.25','TCP'],['172.31.69.25','18.218.229.235','TCP'],
                                                   ['18.218.11.51','172.31.69.25','TCP'],['172.31.69.25','18.218.11.51','TCP'],
                                                   ['18.216.24.42','172.31.69.25','TCP'],['172.31.69.25','18.216.24.42','TCP']],
                    '14_02_wed_ssh_bruteforce':[['13.58.98.64','172.31.69.25','TCP'],['172.31.69.25','13.58.98.64','TCP']],
                    '21_02_ddos_hoic':[['18.218.115.60','172.31.69.28','TCP'],['172.31.69.28','18.218.115.60','TCP'],
                                                   ['18.219.9.1','172.31.69.28','TCP'],['172.31.69.28','18.219.9.1','TCP'],
                                                   ['18.219.32.43','172.31.69.28','TCP'],['172.31.69.28','18.219.32.43','TCP'],
                                                   ['18.218.55.126','172.31.69.28','TCP'],['172.31.69.28','18.218.55.126','TCP'],
                                                   ['52.14.136.135','172.31.69.28','TCP'],['172.31.69.28','52.14.136.135','TCP'],
                                                   ['18.219.5.43','172.31.69.28','TCP'],['172.31.69.28','18.219.5.43','TCP'],
                                                   ['18.216.200.189','172.31.69.28','TCP'],['172.31.69.28','18.216.200.189','TCP'],
                                                   ['18.218.229.235','172.31.69.28','TCP'],['172.31.69.28','18.218.229.235','TCP'],
                                                   ['18.218.11.51','172.31.69.28','TCP'],['172.31.69.28','18.218.11.51','TCP'],
                                                   ['18.216.24.42','172.31.69.28','TCP'],['172.31.69.28','18.216.24.42','TCP']],
                    '16_02_friday_dos_hulk':[['18.219.193.20','172.31.69.25','TCP'],['172.31.69.25','18.219.193.20','TCP']]} 
    
    

    for attack in attacks:

                
        # =============================================================================
        # generate normal/abnormal pcap
        # =============================================================================
      
        print(attack)
        pkts = rdpcap('../datasets/raw_datasets/cse-cic-ids2018/Original Network Traffic and Log data/attack_dataset/' + attack + '.pcap')
        
        
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
                            pass

                    except ValueError:
                        print('verror')
                        pass
                    except AttributeError:
                        print('aerror')
                        pass
                if(tuple5 in normal_flow):
                    normal_pcap.append(pkt)
                elif(tuple5 in abnormal_flow[attack]):
                    abnormal_pcap.append(pkt)

            
        wrpcap("../datasets/split_benign_attack/cicids2018/normal_" + attack + ".pcap", normal_pcap)
        wrpcap("../datasets/split_benign_attack/cicids2018/abnormal_" + attack + ".pcap", abnormal_pcap)
        
