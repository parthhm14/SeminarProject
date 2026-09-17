"""
Model Training Module.
Trains Baseline (Logistic Regression) and Advanced (Random Forest) ML models
with leak-proof train/test splitting and saves model binaries.
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

import config
from dataset import prepare_and_save_datasets
from features import CodeFeaturePipeline

def train_vulnerability_detectors():
    """
    Executes the training pipeline:
    1. Loads or generates dataset
    2. Performs stratified 80/20 train-test split
    3. Fits feature pipeline on training data ONLY to prevent data leakage
    4. Trains Baseline (Logistic Regression) and Advanced (Random Forest) models
    5. Saves trained pipeline and models to disk
    """
    if not os.path.exists(config.DATASET_PATH):
        df, _ = prepare_and_save_datasets()
    else:
        df = pd.read_csv(config.DATASET_PATH)

    print(f"\n[+] Loaded dataset with {len(df)} samples.")
    X_raw = df['code'].values
    y = df['label'].values

    # Stratified Train/Test Split
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw, y,
        test_size=config.TEST_SIZE,
        random_state=config.RANDOM_SEED,
        stratify=y
    )

    print(f"    Train Split: {len(X_train_raw)} samples (Safe: {sum(y_train==0)}, Vulnerable: {sum(y_train==1)})")
    print(f"    Test Split:  {len(X_test_raw)} samples (Safe: {sum(y_test==0)}, Vulnerable: {sum(y_test==1)})")

    # Feature Extraction Pipeline
    print("\n[+] Extracting hybrid features (TF-IDF + C/C++ Security Domain)...")
    feature_pipeline = CodeFeaturePipeline()
    X_train = feature_pipeline.fit_transform(X_train_raw)
    X_test = feature_pipeline.transform(X_test_raw)
    print(f"    Total Feature Vector Dimensions: {X_train.shape[1]}")

    # 1. Baseline Model: Logistic Regression
    print("\n[+] Training Baseline Model (Logistic Regression)...")
    baseline_model = LogisticRegression(**config.LOGISTIC_REGRESSION_PARAMS)
    baseline_model.fit(X_train, y_train)

    # 2. Advanced Model: Random Forest Classifier
    print("[+] Training Advanced Model (Random Forest)...")
    advanced_model = RandomForestClassifier(**config.RANDOM_FOREST_PARAMS)
    advanced_model.fit(X_train, y_train)

    # Save artifacts
    print("\n[+] Saving trained model binaries...")
    joblib.dump(feature_pipeline, config.VECTORIZER_PATH)
    joblib.dump(baseline_model, config.BASELINE_MODEL_PATH)
    joblib.dump(advanced_model, config.ADVANCED_MODEL_PATH)
    
    print(f"    Saved Feature Pipeline to: {config.VECTORIZER_PATH}")
    print(f"    Saved Baseline Model to:    {config.BASELINE_MODEL_PATH}")
    print(f"    Saved Advanced Model to:    {config.ADVANCED_MODEL_PATH}")

    return {
        "feature_pipeline": feature_pipeline,
        "baseline_model": baseline_model,
        "advanced_model": advanced_model,
        "X_train_raw": X_train_raw,
        "X_test_raw": X_test_raw,
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test
    }

if __name__ == "__main__":
    train_vulnerability_detectors()
