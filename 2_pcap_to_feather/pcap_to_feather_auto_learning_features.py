#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 12 16:55:14 2024

@author: didik
"""

from scapy.all import *
import itertools
import numpy as np
import random
import socket
import struct
import subprocess
import os
import glob
import pandas as pd

#%%

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

def mergecap(filename1, filename2, folder_path):
    p1 = subprocess.Popen(['mergecap','-w', folder_path + 'merged.pcap', filename1, filename2])
    p1.wait()  # wait for the first subprocess to finish
    subprocess.Popen(['rm', filename1, filename2])
    
#%%

def extract_packet(data_dir, save_place, filename, label):
    
    all_data_packet_df = pd.DataFrame()
    all_data_packet_np = []
    folder_path = data_dir

    os.chdir(folder_path)
    extension = 'pcap'
    
    full_data = []
    one_data = []
    all_filenames = [i for i in glob.glob('*.{}'.format(extension))]
    
    for fff in all_filenames:
        # print(fff)
        pkts = rdpcap(fff)
        s_pkts = pkts.sessions()

        del_keys = []
        for key in del_keys:
            s_pkts.__delitem__(key)
    
        # Sessions into flow, each flow is bidirectional and identified by 5-tuple
        
        f_pkts = []

        for i,j in itertools.combinations(s_pkts.keys(),2):
                
            if [p in j for p in i.split(' ')].count(False) == 0:
                
                aa = s_pkts[i]
                bb = s_pkts[j]
                pkt_count = 0
    
                for pkt in aa:
                    pkt_count +=1
                for pkt in bb:
                    pkt_count +=1
                
    
                if pkt_count >= 2050:
                    filename1=folder_path+i+'.pcap'
                    filename2=folder_path+j+'.pcap'
                    wrpcap(filename1, aa)
                    wrpcap(filename2, bb)
                    mergecap(filename1, filename2, folder_path)
                    time.sleep(10)
                    mergedfile = rdpcap(folder_path+'merged.pcap')
                    f_pkts.append(mergedfile)
                    subprocess.Popen(['rm', folder_path + 'merged.pcap'])
                else:    
                    f_pkts.append(sortappend(s_pkts[i],s_pkts[j]))
                    
        del s_pkts
        del del_keys
        del pkts    
    
        # Processing flow data to input data
    
        data=[] 
        
        img_shape=(150,10) 
        for flow in f_pkts: 
            f = []
            for pkt in flow[:img_shape[1]]: 
                if(pkt.payload.name == 'ARP'):
                    #random IP
                    pkt.payload.psrc = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                    pkt.payload.pdst = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                elif(pkt.payload.name == 'IP'):
                    #random IP
                    pkt.payload.src = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                    pkt.payload.dst = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                #random MAC
                pkt.src = rand_mac()
                pkt.dst = rand_mac()
                #random port
                pkt.payload.payload.sport = random.randint(1, 0xffff)
                pkt.payload.payload.dport = random.randint(1, 0xffff)
                #packet -> bytes
                pkt_50 = [field for field in raw(pkt)] 
                pkt_50.extend([0]*img_shape[0])
                f.extend(pkt_50[:img_shape[0]])
            #deal with pcaket<3
            if(img_shape[1]-len(flow) > 0):
                f.extend([0]*img_shape[0]*(img_shape[1]-len(flow)))
            data.append(f)
            data_packet = pd.DataFrame(data)
            
        all_data_packet_np.append(data)
        all_data_packet_df = pd.concat([all_data_packet_df, data_packet], ignore_index = True)
    
    all_data_packet_df['label'] = label 
    
    
    all_data_packet_df.columns = all_data_packet_df.columns.map(str)

    all_data_packet_df.reset_index(drop=True).to_feather(f"{save_place}{filename}.feather")
    return all_data_packet_df


if __name__ == '__main__':

    datasets = {
    'cremev2': ['disk_wipe', 'ransomware', 'mirai', 'resource_hijacking', 'end_point_dos', 'benign'],
    'cremev1': ['disk_wipe', 'ransomware', 'mirai', 'resource_hijacking', 'end_point_dos', 'benign'],
    'cicids2017': ['botnet', 'brute_force_ssh', 'ddos', 'dos', 'infiltration', 'port_scan', 'web_attack', 'benign'],
    'cicids2018': ['botnet', 'brute_force', 'ddos', 'ddos_loic', 'ddos_hoic', 'dos', 'infiltration', 'web_attack', 'benign'],
    'cicddos2019': ['cicddos2019'],
    'mirai_ccu': ['benign_mirai_ccu', 'mirai_ccu']
    }

    base_path = 'datasets/'
    for dataset, attacks in datasets.items():
        save_place = f'{base_path}extracted_data/auto_learning/{dataset}/'
        for attack in attacks:
            if dataset in ['cremev2', 'cremev1']:
                label = '0' if attack == 'benign' else '1'
            else:
                label = '0' if 'benign' in attack else '1'
            extract_packet(f'{base_path}{dataset}/{"" if attack == "benign" else attack + "/"}', save_place, attack, label)

        


    

