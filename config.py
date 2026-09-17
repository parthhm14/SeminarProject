"""
Configuration module for ML-Assisted Security Evaluation of AI-Generated C/C++ Code.
Student: Parth Mundra (Roll No: 24CSE1035), NIT Goa
"""

import os

# Base Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

# Ensure required output directories exist
os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# Dataset Paths
DATASET_PATH = os.path.join(DATASET_DIR, "cpp_vulnerabilities_dataset.csv")
AI_PATCHES_PATH = os.path.join(DATASET_DIR, "ai_generated_patches.json")

# Saved Model Paths
BASELINE_MODEL_PATH = os.path.join(MODELS_DIR, "baseline_logistic_regression.joblib")
ADVANCED_MODEL_PATH = os.path.join(MODELS_DIR, "advanced_random_forest.joblib")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "feature_extractor.joblib")

# Results Paths
METRICS_PATH = os.path.join(RESULTS_DIR, "evaluation_metrics.json")
AI_EVAL_RESULTS_PATH = os.path.join(RESULTS_DIR, "ai_patch_evaluation.json")

# Hyperparameters & Random Seeds
RANDOM_SEED = 42
TEST_SIZE = 0.20

# Feature Extraction Settings
TFIDF_MAX_FEATURES = 1000
NGRAM_RANGE = (1, 3)

# Model Settings
LOGISTIC_REGRESSION_PARAMS = {
    'C': 1.0,
    'max_iter': 1000,
    'random_state': RANDOM_SEED,
    'class_weight': 'balanced'
}

RANDOM_FOREST_PARAMS = {
    'n_estimators': 150,
    'max_depth': 15,
    'random_state': RANDOM_SEED,
    'class_weight': 'balanced',
    'n_jobs': -1
}
