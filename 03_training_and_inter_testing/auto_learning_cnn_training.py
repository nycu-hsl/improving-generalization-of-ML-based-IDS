#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Nov 12 22:41:55 2023

@author: didik
"""
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
#CNN
from tensorflow.keras.layers import Flatten, Dense, Conv1D, MaxPool1D, Dropout
import tensorflow as tf
import matplotlib.pyplot as plt
from tensorflow.keras.models import load_model
# from keras.utils import np_utils
from keras.models import Model
# from keras.layers.normalization import BatchNormalization
from keras.layers import Dense, Activation, Flatten, Conv1D, MaxPooling1D, Input
from keras.optimizers import Adam
import os
from sklearn.metrics import confusion_matrix
from keras.utils import plot_model
from sklearn.utils import shuffle
from sklearn import metrics
from sklearn.metrics import accuracy_score
from keras import backend as K
import glob

from tensorflow.keras.layers import BatchNormalization
from tensorflow.keras.metrics import TruePositives, FalsePositives, FalseNegatives

from imblearn.over_sampling import SMOTE
from tensorflow.keras.utils import to_categorical
from sklearn import preprocessing

combinations = [
    (3, 60), (3, 70), (3, 80),
    (4, 60), (4, 70), (4, 80),
    (5, 60), (5, 70), (5, 80),
    (6, 60), (6, 70), (6, 80),
]

output_directory = "CNN_model"

# Construct the filename
filename = f"{output_directory}/CNN_{num_packets}_packets_{bytes_per_packet}_bytes.h5"

def reduce_features_by_packets(df, num_packets=1):
    """
    Reduce the dataframe to include only the specified number of packets,
    keeping all bytes for those packets, while preserving the last column for labels.
    """
    max_feature = num_packets * 256
    # Preserving the last column
    reduced_df = pd.concat([df.iloc[:, :max_feature], df.iloc[:, -1]], axis=1)
    return reduced_df

def reduce_features_by_bytes(df, num_bytes, num_packets):
    """
    Reduce the dataframe to include only the specified number of bytes per packet,
    for the specified number of packets, while preserving the last column for labels.
    """
    selected_features = []
    for packet in range(num_packets):
        start_feature = packet * 256
        end_feature = start_feature + num_bytes
        selected_features.extend(range(start_feature, end_feature))
    # Preserving the last column
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
    """
    Reduce the DataFrame to include only the specified number of packets and bytes per packet,
    and remove specified features based on the remove parameters, while preserving the last column for labels.
    """
    # Ensure we work on a copy to prevent modifying the original DataFrame
    df_reduced = df.copy()
    
    # Calculate the total number of features to consider (excluding the label column)
    total_features = num_packets * bytes_per_packet
    # Adjust remove_params to ensure we don't attempt to remove the label column
    remove_params_adjusted = [param for param in remove_params if param < total_features]
    
    # Reduce to the specified number of bytes per packet, excluding the label column from removal
    selected_features = []
    for packet in range(num_packets):
        start_feature = packet * bytes_per_packet
        end_feature = start_feature + bytes_per_packet
        packet_features = list(range(start_feature, end_feature))
        # Remove specified features for this packet
        packet_features = [f for f in packet_features if f not in remove_params_adjusted]
        selected_features.extend(packet_features)
    
    # Ensure the label column is preserved by adding its index
    selected_features.append(len(df.columns) - 1)  # Add index of the last column
    
    # Select only the relevant features, including the label column
    df_reduced = df_reduced.iloc[:, selected_features]
    return df_reduced

def read_and_sample_feather_files(file, label_column='label', bytes_per_packet=bytes_per_packet, num_packets=num_packets):
    """
    Reads and samples feather files from a directory, performing downsampling and feature reduction.
    """
    file = pd.read_feather(file)
    file = reduce_features_by_bytes(file, bytes_per_packet, num_packets)
    remove_params = generate_remove_parameters(num_packets, bytes_per_packet)
    file = reduce_features(file, num_packets, bytes_per_packet, remove_params)
    
    return file

def recall_m(y_true, y_pred):
    true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
    possible_positives = K.sum(K.round(K.clip(y_true, 0, 1)))
    recall = true_positives / (possible_positives + K.epsilon())
    return recall

def precision_m(y_true, y_pred):
    true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
    predicted_positives = K.sum(K.round(K.clip(y_pred, 0, 1)))
    precision = true_positives / (predicted_positives + K.epsilon())
    return precision

def f1_m(y_true, y_pred):
    precision = precision_m(y_true, y_pred)
    recall = recall_m(y_true, y_pred)
    return 2*((precision*recall)/(precision+recall+K.epsilon()))


def train_model_for_configuration(num_packets, bytes_per_packet):
    benign = read_and_sample_feather_files('extracted_data/cremev2/benign.feather')
    disk_wipe = read_and_sample_feather_files('extracted_data/cremev2/disk_wipe.feather')
    end_point_dos = read_and_sample_feather_files('extracted_data/cremev2/end_point_dos.feather')
    mirai = read_and_sample_feather_files('extracted_data/cremev2/mirai.feather')
    ransomware = read_and_sample_feather_files('extracted_data/cremev2/ransomware.feather')
    resource_hijacking = read_and_sample_feather_files('extracted_data/cremev2/resource_hijacking.feather')

    benign['label'] = 0
    disk_wipe['label'] = 1
    end_point_dos['label'] = 1
    mirai['label'] = 1
    ransomware['label'] = 1
    resource_hijacking['label'] = 1

    df = pd.concat([benign, disk_wipe, end_point_dos, mirai, ransomware, resource_hijacking])

    ### Delete all these variables to save up RAM
    del benign
    del disk_wipe
    del end_point_dos
    del mirai
    del ransomware
    del resource_hijacking

    label_dataset = df['label'].value_counts()
    print(label_dataset)

    X = df.iloc[:,:-1].values #independent values / features
    y = df.iloc[:,-1].values #dependent values / target

    del df


    print(f"Number of rows: {X.shape[0]}, Number of columns: {X.shape[1]}")

    # Split the data into training, validation, and test sets
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
    X_val, X_test, y_val, y_test = train_test_split(X_val, y_val, test_size=0.2, stratify=y_val, random_state=42)

    oversample = SMOTE()
    X_train, y_train = oversample.fit_resample(X_train, y_train)

    #size for the sets
    print('size of X_train:', X_train.shape)
    print('size of X_test:', X_test.shape)
    print('size of y_train:', y_train.shape)
    print('size of y_test:', y_test.shape)

    #Reshape train and test data to (n_samples, 187, 1), where each sample is of size (187, 1)
    X_train = np.array(X_train).reshape(X_train.shape[0], X_train.shape[1], 1)/255
    X_val = np.array(X_val).reshape(X_val.shape[0], X_val.shape[1], 1)/255
    X_test = np.array(X_test).reshape(X_test.shape[0], X_test.shape[1], 1)/255
    print("X Train shape: ", X_train.shape)
    print("X Test shape: ", X_test.shape)

    #size for the sets
    print('size of X_train:', X_train.shape)
    print('size of X_test:', X_test.shape)
    print('size of y_train:', y_train.shape)
    print('size of y_test:', y_test.shape)

    #Reshape train and test data to (n_samples, 187, 1), where each sample is of size (187, 1)
    X_train = np.array(X_train).reshape(X_train.shape[0], X_train.shape[1], 1)/255
    X_val = np.array(X_val).reshape(X_val.shape[0], X_val.shape[1], 1)/255
    X_test = np.array(X_test).reshape(X_test.shape[0], X_test.shape[1], 1)/255
    print("X Train shape: ", X_train.shape)
    print("X Test shape: ", X_test.shape)
    #%%
        # =============================================================================
        # model
        # =============================================================================
    inputs = Input(shape=(X_train.shape[1],1))
    # inputs = Input(shape=(img_shape[0],img_shape[1]))
    CNN_con1 = Conv1D(
        filters=32, ##sebelumnya 32
        kernel_size=6,
        strides=1,
        padding='same',	 # Padding method
    )(inputs)
            
    CNN_con1_1 = BatchNormalization()(CNN_con1)
    CNN_con1_2 = Activation('relu')(CNN_con1_1)
            
    # Pooling layer 1 (max pooling) output shape (32, 14, 14)
    CNN_pool1 = MaxPooling1D(
        pool_size=2, strides=2,
        padding='same',	# Padding method
        )(CNN_con1_2)
            
    CNN_pool1_1 = BatchNormalization()(CNN_pool1)
    CNN_pool1_2 = Activation('relu')(CNN_pool1_1)
            

                    
    # Fully connected layer 1 input shape (64 * 7 * 7) = (3136), output shape (1024)
    flatten = Flatten()(Activation('relu')(BatchNormalization()(CNN_pool1_2)))
    # flatten = Dropout(0.5)(flatten)
            
    CNN_pre_1 = Dense(1)(flatten)
    CNN_pre_1a = Activation('sigmoid')(CNN_pre_1)		
    CNN_pre_1m = Model(inputs,CNN_pre_1a)		
            
    CNN_dense1 = Dense(1024)(flatten)
    CNN_dense1_1 = Activation('relu')(BatchNormalization()(CNN_dense1))
            
    CNN_pre_2 = Dense(1)(CNN_dense1_1)
    CNN_pre_2a = Activation('sigmoid')(CNN_pre_2)		
    CNN_pre_2m = Model(inputs,CNN_pre_2a)
            
    # Fully connected layer 2 to shape (10) for 10 classes
    CNN_dense2 = Dense(15)(CNN_dense1_1)
    CNN_dense2_1 = Activation('relu')(BatchNormalization()(CNN_dense2))
            
    CNN_dense3 = Dense(1, activation= 'sigmoid')(CNN_dense2_1)

    CNN = Model(inputs,CNN_dense3)
    # Another way to define your optimizer
    adam = Adam(lr=1e-5)

    CNN_pre_1m.compile(optimizer=adam, loss='binary_crossentropy', metrics=['accuracy'])
    CNN_pre_2m.compile(optimizer=adam, loss='binary_crossentropy', metrics=['accuracy'])				
    CNN.compile(optimizer=adam, loss='binary_crossentropy', metrics = ['accuracy',f1_m,precision_m, recall_m]) 
    CNN.summary()
    plot_model(CNN, show_shapes=True, show_layer_names=True)	
    callback = tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=20, mode='min', restore_best_weights=True)


    print('\n--------------------- CNN Flatten Training --------------------')
    CNN_pre_1m.fit(X_train, y_train, epochs=100, batch_size=32,callbacks=[callback], validation_data=(X_val, y_val))
    print('\n--------------------- CNN Dense 1 Training --------------------')
    CNN_pre_2m.fit(X_train, y_train, epochs=100, batch_size=32,callbacks=[callback], validation_data=(X_val, y_val))
    print('\n------------------------ CNN Training ------------------------')
    CNN.fit(X_train, y_train, epochs=100, batch_size=32,callbacks=[callback], validation_data=(X_val, y_val))	

    #testing		  		
    print('\n------------------------ CNN Testing ------------------------')
    pre_cls=CNN.predict(X_test)
    for i in range(len(pre_cls)):
        if(pre_cls[i] < 0.5):
            pre_cls[i] = 0
        else:
            pre_cls[i] = 1
    tn, fp, fn, tp = confusion_matrix(y_test, pre_cls).ravel()
    print("TN:", tn, "FP:", fp, "FN:", fn, "TP:", tp)
    print("Accuracy:", accuracy_score(y_test, pre_cls))
    print("F1-score:", metrics.f1_score(y_test, pre_cls))

    #save\load model
    CNN.save(filename)

# Loop through each configuration and train the model
for num_packets, bytes_per_packet in combinations:
    train_model_for_configuration(num_packets, bytes_per_packet)
