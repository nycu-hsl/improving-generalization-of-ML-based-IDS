#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 27 17:35:39 2024

@author: didik
"""

import os
# Set environment variables
os.environ['CUDA_VISIBLE_DEVICES'] = ''
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
from keras import backend as K
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score



# Data reduction functions
def reduce_features_by_packets(df, num_packets):
    max_feature = num_packets * 256
    reduced_df = pd.concat([df.iloc[:, :max_feature], df.iloc[:, -1]], axis=1)
    return reduced_df

def reduce_features_by_bytes(df, num_bytes, num_packets):
    selected_features = [i for packet in range(num_packets) for i in range(packet * 256, packet * 256 + num_bytes)]
    reduced_df = pd.concat([df.iloc[:, selected_features], df.iloc[:, -1]], axis=1)
    return reduced_df

def generate_remove_parameters(num_packets, bytes_per_packet):
    """
    Generate a list of feature indices to remove based on the number of packets and bytes per packet.
    Adjusts the indices for each packet according to the specified layout.
    """
    remove_indices = []
    base_remove_params = [
        # Source MAC Address
        0, 1, 2, 3, 4, 5,
        # Destination MAC Address
        6, 7, 8, 9, 10, 11,
        # Source IP Address
        26, 27, 28, 29,
        # Destination IP Address
        30, 31, 32, 33,
        # Source Port
        34, 35,
        # Destination Port
        36, 37
    ]
    for packet in range(num_packets):
        packet_offset = packet * bytes_per_packet
        remove_indices.extend([i + packet_offset for i in base_remove_params])
    return remove_indices

def reduce_features(df, num_packets, bytes_per_packet, remove_params=[]):
    total_features = num_packets * bytes_per_packet
    remove_params_adjusted = [param for param in remove_params if param < total_features]
    selected_features = [f for packet in range(num_packets) for f in range(packet * bytes_per_packet, (packet + 1) * bytes_per_packet) if f not in remove_params_adjusted]
    selected_features.append(df.shape[1] - 1)  # Add label column index
    df_reduced = df.iloc[:, selected_features]
    return df_reduced

def read_and_sample_feather(file, num_packets, bytes_per_packet):
    df = pd.read_feather(file)
    df = reduce_features_by_bytes(df, bytes_per_packet, num_packets)
    remove_params = generate_remove_parameters(num_packets, bytes_per_packet)
    df = reduce_features(df, num_packets, bytes_per_packet, remove_params)
    return df

# Metrics functions
def recall_m(y_true, y_pred):
    return K.sum(K.round(K.clip(y_true * y_pred, 0, 1))) / K.sum(K.round(K.clip(y_true, 0, 1)) + K.epsilon())

def precision_m(y_true, y_pred):
    return K.sum(K.round(K.clip(y_true * y_pred, 0, 1))) / K.sum(K.round(K.clip(y_pred, 0, 1)) + K.epsilon())

def f1_m(y_true, y_pred):
    precision = precision_m(y_true, y_pred)
    recall = recall_m(y_true, y_pred)
    return 2 * ((precision * recall) / (precision + recall + K.epsilon()))

def calculate_metrics(y_true, y_pred):
    # Convert both y_true and y_pred to the same type (integers in this case)
    y_true = y_true.astype(int)
    y_pred = y_pred.astype(int)
    
    # Now calculate the metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)  # Add zero_division parameter to handle divide by zero cases
    recall = recall_score(y_true, y_pred, zero_division=0)        # Same here for consistency
    f1 = f1_score(y_true, y_pred, zero_division=0)                # And here as well

    return accuracy, precision, recall, f1

# Loop through combinations of num_packets and bytes_per_packet
num_packets_options = [3, 4, 5, 6]
bytes_per_packet_options = [60, 70, 80]
dataset_paths = [
    '../datasets/extracted_data/auto_learning/inter_dataset_testing_data/cremev2_test.feather',
    '../datasets/extracted_data/auto_learning/inter_dataset_testing_data/cremev1_test.feather',
    '../datasets/extracted_data/auto_learning/inter_dataset_testing_data/cicids2017_test.feather',
    '../datasets/extracted_data/auto_learning/inter_dataset_testing_data/cicids2018_test.feather',
    '../datasets/extracted_data/auto_learning/inter_dataset_testing_data/cicddos2019_test.feather',
    '../datasets/extracted_data/auto_learning/inter_dataset_testing_data/mirai_ccu_test.feather'
]

# Names of datasets for clarity in results
dataset_names = ['CREMEv2', 'CREMEv1', 'CIC-IDS-2017', 'CIC-IDS-2018', 'CIC-DDOS-2019', 'CCU-Mirai HTTP']

# Initialize directory for storing models
CNN_directory = "../CNN_model/"
# Prepare an empty DataFrame for storing results
results_df = pd.DataFrame(columns=['Num Packets', 'Bytes per Packet', 'Dataset', 'Accuracy', 'Precision', 'Recall', 'F1 Score'])


# Loop through all combinations
for num_packets in num_packets_options:
    for bytes_per_packet in bytes_per_packet_options:
        # Load model for this configuration
        CNN_file = f"{CNN_directory}/CNN_{num_packets}_packets_{bytes_per_packet}_bytes.h5"
        savedModel = load_model(CNN_file, custom_objects={'recall_m': recall_m, 'f1_m': f1_m, 'precision_m': precision_m})

        metrics_data = {'Dataset': dataset_names}
        metrics_keys = ['Accuracy', 'Precision', 'Recall', 'F1 Score']

        # Loop through each dataset
        for dataset_path, dataset_name in zip(dataset_paths, dataset_names):
            # Preprocess dataset
            dataset = read_and_sample_feather(dataset_path, num_packets, bytes_per_packet)
            X = np.array(dataset.iloc[:, :-1].values).reshape(dataset.shape[0], dataset.shape[1] - 1, 1) / 255
            Y = dataset.iloc[:, -1].values

            # Make predictions
            Y_pred = savedModel.predict(X)
            Y_pred = np.where(Y_pred < 0.5, 0, 1)

            # Calculate and store metrics
            accuracy, precision, recall, f1 = calculate_metrics(Y, Y_pred)
            for metric_key, metric_value in zip(metrics_keys, [accuracy, precision, recall, f1]):
                if metric_key not in metrics_data:
                    metrics_data[metric_key] = []
                metrics_data[metric_key].append(metric_value)

        # Output the metrics for this combination
        print(f"\nMetrics for num_packets={num_packets}, bytes_per_packet={bytes_per_packet}:")
        for key, values in metrics_data.items():
            print(f"{key}: {values}")
            
        for i, dataset_name in enumerate(dataset_names):
            row = {
                'Num Packets': num_packets,
                'Bytes per Packet': bytes_per_packet,
                'Dataset': dataset_name,
                'Accuracy': metrics_data['Accuracy'][i],
                'Precision': metrics_data['Precision'][i],
                'Recall': metrics_data['Recall'][i],
                'F1 Score': metrics_data['F1 Score'][i]
            }
            # Append the row to the DataFrame
            results_df = results_df.append(row, ignore_index=True)

        # Optionally, you can store these metrics in a more permanent way (e.g., appending to a CSV file)
# Save the complete results to CSV
results_df.to_csv('model_performance_results.csv', index=False)
