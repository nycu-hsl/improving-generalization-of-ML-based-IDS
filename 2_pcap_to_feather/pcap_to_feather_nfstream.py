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
from nfstream import NFStreamer, NFPlugin

#%%
remove_parameter = [
    'id',
  'expiration_id',
  'src_ip',
  'src_mac',
  'src_oui',
  'src_port',
    'dst_oui',
    'dst_port',
  'dst_ip',
    'dst_mac',
    'dst_mac',
    'ip_version',
    'vlan_id',
    'tunnel_id',
    'application_name',
    'application_category_name',
    'application_is_guessed',
    'application_confidence',
    'requested_server_name',
    'client_fingerprint',
    'server_fingerprint',
    'user_agent',
    'content_type',
    'Unnamed: 0',
    'index',
        'bidirectional_first_seen_ms',
  'bidirectional_last_seen_ms',
  'src2dst_first_seen_ms',
  'src2dst_last_seen_ms',
  'dst2src_first_seen_ms',
  'dst2src_last_seen_ms'
]

def remove_param(df):
    for total_remove_parameter in range (0, len(remove_parameter)):
        for feature in range(0, len(df.columns)):
            if remove_parameter[total_remove_parameter] == df.columns[feature]:
                df = df.drop(columns=remove_parameter[total_remove_parameter])
                break
            
    return df

def remove_inf_nan(df):
    
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    #print(f"{df.isna().any(axis=1).sum()} invalid rows dropped")
    df.dropna(inplace=True)
    
    remove_rows_with_str = dict()
    
    
    return df

def extract_flow(data_dir, result_path, class_name, label):
    
    os.chdir(data_dir)
    extension = 'pcap'
    all_data = pd.DataFrame()
    
    all_filenames = [i for i in glob.glob('*.{}'.format(extension))]
    
    for f in all_filenames:
        df = NFStreamer(source=f, statistical_analysis=True).to_pandas()
        df = remove_param(df)
        df = remove_inf_nan(df)
        df['label'] = label
        all_data = pd.concat([all_data,df], ignore_index=True)
        
    all_data.reset_index(drop=True).to_feather(result_path + class_name + ".feather")
    return all_data

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
        save_place = f'{base_path}extracted_data/nfstream/{dataset}/'
        for attack in attacks:
            if dataset in ['cremev2', 'cremev1']:
                label = '0' if attack == 'benign' else '1'
            else:
                label = '0' if 'benign' in attack else '1'
            extract_flow(f'{base_path}{dataset}/{"" if attack == "benign" else attack + "/"}', save_place, attack, label)

        


    

