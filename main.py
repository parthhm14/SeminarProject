"""
Master Orchestration Script for ML-Assisted Security Evaluation of AI-Generated C/C++ Code.
Executes the end-to-end pipeline: Data Prep -> Model Training -> Evaluation -> AI Patch Testing -> Plotting.
Student: Parth Mundra (Roll No: 24CSE1035), NIT Goa
"""

import sys
import time
import json
import config
from dataset import prepare_and_save_datasets
from train import train_vulnerability_detectors
from evaluate import evaluate_models
from ai_patch_evaluator import evaluate_ai_generated_patches
from visualize import generate_all_plots

def run_pipeline():
    start_time = time.time()
    print("=" * 70)
    print("      ML-ASSISTED SECURITY EVALUATION OF AI-GENERATED C/C++ CODE     ")
    print("      Seminar Research Project | Parth Mundra (24CSE1035) | NIT Goa   ")
    print("=" * 70)

    # 1. Dataset Preparation
    print("\n---> STEP 1: Preparing Datasets & AI Benchmark Suite")
    df, ai_patches = prepare_and_save_datasets()

    # 2. Model Training
    print("\n---> STEP 2: Training Baseline and Advanced ML Vulnerability Detectors")
    train_results = train_vulnerability_detectors()

    # 3. Model Evaluation on Test Split
    print("\n---> STEP 3: Evaluating Models & Error Analysis")
    metrics = evaluate_models(train_results)

    # 4. AI Patch Evaluation Matrix
    print("\n---> STEP 4: Evaluating AI-Generated C/C++ Patches (SecureVibeBench Oracles)")
    ai_results = evaluate_ai_generated_patches()

    # 5. Visualizations
    print("\n---> STEP 5: Generating Publication-Quality Figures")
    generate_all_plots(train_results)

    elapsed_time = time.time() - start_time
    print("\n" + "=" * 70)
    print("                      PIPELINE EXECUTION COMPLETE                   ")
    print(f" Total Execution Time: {elapsed_time:.2f} seconds")
    print(f" Saved Model Directory: {config.MODELS_DIR}")
    print(f" Saved Results Directory: {config.RESULTS_DIR}")
    print("=" * 70)

if __name__ == "__main__":
    run_pipeline()
