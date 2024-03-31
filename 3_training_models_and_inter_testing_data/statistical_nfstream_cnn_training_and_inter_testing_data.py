#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 31 17:36:17 2024

@author: didik
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier
import glob
import warnings
warnings.filterwarnings("ignore", category=UserWarning) 

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 
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

# Set fixed values for reproducibility
SEED_VALUE = 42
os.environ['PYTHONHASHSEED'] = str(SEED_VALUE)
np.random.seed(SEED_VALUE)
import tensorflow as tf
tf.random.set_seed(SEED_VALUE)
threshold_b = 0.5

def load_data(file_paths, sample_size=None, random_state=42):
    """Load and optionally sample data from given file paths, converting multi-class to binary labels."""
    df_list = []
    for path in file_paths:
        df = pd.read_feather(path)
        if 'label' in df.columns:
            # Convert labels: 0 remains 0, everything else becomes 1
            df['label'] = df['label'].apply(lambda x: 1 if x != 0 else 0)
        if sample_size and len(df) > sample_size:
            df = df.sample(n=sample_size, random_state=random_state)
        df_list.append(df)
    return pd.concat(df_list, ignore_index=True)


def load_and_combine_datasets(main_paths, benign_path, main_sample_size, benign_sample_size, random_state=42):
    """Load main and benign datasets, sample them, and combine."""
    main_df = load_data(main_paths, sample_size=main_sample_size, random_state=random_state)
    benign_df = load_data([benign_path], sample_size=benign_sample_size, random_state=random_state) if benign_path else pd.DataFrame()
    combined_df = pd.concat([main_df, benign_df], ignore_index=True) if not benign_df.empty else main_df
    return combined_df

def prepare_data(df, scaler=None, target='label'):
    """Preprocess data, split into features and labels, and apply scaling."""
    X = df.drop(columns=[target])
    y = df[target]
    if scaler:
        X = scaler.transform(X)
    X = np.array(X).reshape(X.shape[0], X.shape[1], 1)
    return X, y

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

def train_model(X_train, y_train, X_val, y_val):
    """Train the CNN model."""
    inputs = Input(shape=(X_train.shape[1],1))
    # inputs = Input(shape=(img_shape[0],img_shape[1]))
    CNN_con1 = Conv1D(
        filters=32,
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
      		
    CNN_pre_1 = Dense(1)(flatten)
    CNN_pre_1a = Activation('sigmoid')(CNN_pre_1)		
    CNN_pre_1m = Model(inputs,CNN_pre_1a)		
      		
    CNN_dense1 = Dense(1024)(flatten)
    CNN_dense1_1 = Activation('relu')(BatchNormalization()(CNN_dense1))
      		
    CNN_pre_2 = Dense(1)(CNN_dense1_1)
    CNN_pre_2a = Activation('sigmoid')(CNN_pre_2)		
    CNN_pre_2m = Model(inputs,CNN_pre_2a)
      		
    # Fully connected layer 2 to shape (10) for 10 classes
    CNN_dense2 = Dense(25)(CNN_dense1_1)
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
    callback = tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=5, mode='min')


    print('\n--------------------- CNN Flatten Training --------------------')
    CNN_pre_1m.fit(X_train, y_train, epochs=50, batch_size=32,callbacks=[callback], validation_data=(X_val, y_val))
    print('\n--------------------- CNN Dense 1 Training --------------------')
    CNN_pre_2m.fit(X_train, y_train, epochs=50, batch_size=32,callbacks=[callback], validation_data=(X_val,y_val))
    print('\n------------------------ CNN Training ------------------------')
    CNN.fit(X_train, y_train, epochs=50, batch_size=32,callbacks=[callback], validation_data=(X_val,y_val))	
    
    return CNN

def calculate_metrics(y_true, y_pred):
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    return accuracy, precision, recall, f1

def evaluate_model(model, X_test, y_test, dataset_name):
    """Evaluate the model and print out metrics."""
    y_pred = model.predict(X_test)
    y_pred = np.where(y_pred < threshold_b, 0, 1)
    accuracy, precision, recall, f1 = calculate_metrics(y_test, y_pred)
    print(f"{dataset_name} - Accuracy: {accuracy}, Precision: {precision}, Recall: {recall}, F1: {f1}")

def main():
    # Load and preprocess training data
    df_train = load_data(['/media/didik/Backup/dataset_generalization/fix_data_2024/extracted_data/nfstream/cremev2.feather'])
    X = df_train.drop(columns=['label'])
    y = df_train['label']
    X_train, X_val, y_train, y_val = train_test_split(X, y, train_size=0.7, stratify=y, random_state=SEED_VALUE)
    X_val, X_test, y_val, y_test = train_test_split(X_val, y_val, test_size=0.2, stratify=y_val, random_state=SEED_VALUE)
    oversample = SMOTE(random_state=SEED_VALUE)
    X_train, y_train = oversample.fit_resample(X_train, y_train)
    scaler = StandardScaler().fit(X_train)
    X_train = scaler.transform(X_train)
    X_test = scaler.transform(X_test)
    
    X_train = np.array(X_train).reshape(X_train.shape[0], X_train.shape[1], 1)
    X_val = np.array(X_val).reshape(X_val.shape[0], X_val.shape[1], 1)
    X_test = np.array(X_test).reshape(X_test.shape[0], X_test.shape[1], 1)
    
    # Train model
    model = train_model(X_train, y_train, X_val, y_val)
    
    # Evaluate on training set
    evaluate_model(model, X_test, y_test, "CREMEv2 Training Set")

    # Dataset configurations
    datasets_info = {
        "CREMEv1": {
            'main_paths': ['/media/didik/Backup/dataset_generalization/fix_data_2024/extracted_data/nfstream/cremev1.feather'],
            'benign_path': None,
            'main_sample_size': 1000,
            'benign_sample_size': 0
        },
        "CCU-Mirai HTTP": {
            'main_paths': ['/media/didik/Backup/dataset_generalization/fix_data_2024/extracted_data/nfstream/mirai_ccu.feather'],
            'benign_path': None,
            'main_sample_size': 1000,
            'benign_sample_size': 0
        },
        "CIC-IDS-2017": {
            'main_paths': glob.glob('/home/didik/Downloads/code/traffic/preprocess/dataset_cicids_NFStream/*.feather'),
            'benign_path': '/media/didik/01D70E28EC8AF790/Datasets/CICIDS 2017 Raw Data/benign_nfstream/benign.feather',
            'main_sample_size': 1000,
            'benign_sample_size': 5000
        },
        "CIC-IDS-2018": {
            'main_paths': glob.glob('/home/didik/Downloads/code/traffic/preprocess/cicids_2018/nfstream/*.feather'),
            'benign_path': '/media/didik/01D70E28EC8AF790/Datasets/cse-cic-ids2018-benign/Original/benign_2018_july.feather',
            'main_sample_size': 1000,
            'benign_sample_size': 5000
        },
        "CIC-DDOS-2019": {
            'main_paths': glob.glob('/media/didik/01D70E28EC8AF790/Datasets/CICDDOS_2019/dataset/nfstream/*.feather'),
            'benign_path': '/media/didik/01D70E28EC8AF790/Datasets/cse-cic-ids2018-benign/Original/benign_2018_july.feather',
            'main_sample_size': 500,
            'benign_sample_size': 5000
        },
    }
    
    for name, config in datasets_info.items():
        if config['benign_path']:
            df = load_and_combine_datasets(config['main_paths'], config['benign_path'], config['main_sample_size'], config['benign_sample_size'])
        else:
            df = load_data(config['main_paths'], sample_size=config['main_sample_size'])
        X, y = prepare_data(df, scaler)
        evaluate_model(model, X, y, name)

if __name__ == "__main__":
    main()
