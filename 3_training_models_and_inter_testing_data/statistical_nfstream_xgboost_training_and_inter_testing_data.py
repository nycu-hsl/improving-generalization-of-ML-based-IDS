#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 31 16:43:03 2024

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

# Set fixed values for reproducibility
SEED_VALUE = 42
os.environ['PYTHONHASHSEED'] = str(SEED_VALUE)
np.random.seed(SEED_VALUE)
import tensorflow as tf
tf.random.set_seed(SEED_VALUE)

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
    return X, y

def train_model(X_train, y_train):
    """Train the XGBoost model."""
    model = XGBClassifier(objective='binary:logistic', eval_metric='merror', n_jobs=-1, random_state=SEED_VALUE)
    model.fit(X_train, y_train)
    return model

def evaluate_model(model, X_test, y_test, dataset_name):
    """Evaluate the model and print out metrics."""
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='binary', zero_division=0)
    recall = recall_score(y_test, y_pred, average='binary', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='binary', zero_division=0)
    print(f"{dataset_name} - Accuracy: {accuracy}, Precision: {precision}, Recall: {recall}, F1: {f1}")

def main():
    # Load and preprocess training data
    df_train = load_data(['/media/didik/Backup/dataset_generalization/fix_data_2024/extracted_data/nfstream/cremev2.feather'])
    X = df_train.drop(columns=['label'])
    y = df_train['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=0.7, stratify=y, random_state=SEED_VALUE)
    oversample = SMOTE(random_state=SEED_VALUE)
    X_train, y_train = oversample.fit_resample(X_train, y_train)
    scaler = StandardScaler().fit(X_train)
    X_train = scaler.transform(X_train)
    X_test = scaler.transform(X_test)
    
    # Train model
    model = train_model(X_train, y_train)
    
    # Evaluate on training set
    evaluate_model(model, X_test, y_test, "CREMEv2 Training Set")

    # Dataset configurations
    datasets_info = {
        "CREMEv1": {
            'main_paths': ['../datasets/extracted_data/nfstream/cremev1.feather'],
            'benign_path': None,
            'main_sample_size': 1000,
            'benign_sample_size': 0
        },
        "CCU-Mirai HTTP": {
            'main_paths': ['../datasets/extracted_data/nfstream/mirai_ccu.feather'],
            'benign_path': None,
            'main_sample_size': 1000,
            'benign_sample_size': 0
        },
        "CIC-IDS-2017": {
            'main_paths': glob.glob('../datasets/extracted_data/nfstream/cicids2017/*.feather'),
            'benign_path': '../datasets/extracted_data/nfstream/cicids2017/benign/benign_cicids2017.feather',
            'main_sample_size': 1000,
            'benign_sample_size': 5000
        },
        "CIC-IDS-2018": {
            'main_paths': glob.glob('../datasets/extracted_data/nfstream/cicids2018/*.feather'),
            'benign_path': '../datasets/extracted_data/nfstream/cicids2018/benign/benign_cicids2018.feather',
            'main_sample_size': 1000,
            'benign_sample_size': 5000
        },
        "CIC-DDOS-2019": {
            'main_paths': ['..datasets/extracted_data/nfstream/cicddos2019.feather'],
            'benign_path': None,
            'main_sample_size': 0,
            'benign_sample_size': 0
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
