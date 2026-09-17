"""
Model Evaluation and Metrics Computation Module.
Evaluates Baseline and Advanced detectors on test dataset, computes metrics,
saves metrics JSON, and conducts error analysis.
"""

import json
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score
)
import config

def compute_detailed_metrics(y_true, y_pred, y_prob) -> dict:
    """
    Computes comprehensive classification metrics including False Positive Rate (FPR)
    and False Negative Rate (FNR).
    """
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    auc = roc_auc_score(y_true, y_prob)

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1),
        "roc_auc": float(auc),
        "false_positive_rate": float(fpr),
        "false_negative_rate": float(fnr),
        "confusion_matrix": {
            "TN": int(tn),
            "FP": int(fp),
            "FN": int(fn),
            "TP": int(tp)
        }
    }


def evaluate_models(train_results: dict) -> dict:
    """
    Evaluates both Baseline and Advanced models on the test set and performs error analysis.
    """
    X_test_raw = train_results["X_test_raw"]
    X_test = train_results["X_test"]
    y_test = train_results["y_test"]
    baseline_model = train_results["baseline_model"]
    advanced_model = train_results["advanced_model"]

    print("\n[+] Evaluating Baseline Model (Logistic Regression)...")
    y_pred_base = baseline_model.predict(X_test)
    y_prob_base = baseline_model.predict_proba(X_test)[:, 1]
    metrics_base = compute_detailed_metrics(y_test, y_pred_base, y_prob_base)

    print("[+] Evaluating Advanced Model (Random Forest)...")
    y_pred_adv = advanced_model.predict(X_test)
    y_prob_adv = advanced_model.predict_proba(X_test)[:, 1]
    metrics_adv = compute_detailed_metrics(y_test, y_pred_adv, y_prob_adv)

    print("\n=================== EXPERIMENTAL RESULTS ===================")
    print(f"Metric                  Baseline (Logistic)   Advanced (Random Forest)")
    print(f"-------------------------------------------------------------")
    print(f"Accuracy:               {metrics_base['accuracy']:.4f}                {metrics_adv['accuracy']:.4f}")
    print(f"Precision:              {metrics_base['precision']:.4f}                {metrics_adv['precision']:.4f}")
    print(f"Recall (Sensitivity):   {metrics_base['recall']:.4f}                {metrics_adv['recall']:.4f}")
    print(f"F1-Score:               {metrics_base['f1_score']:.4f}                {metrics_adv['f1_score']:.4f}")
    print(f"ROC-AUC Score:          {metrics_base['roc_auc']:.4f}                {metrics_adv['roc_auc']:.4f}")
    print(f"False Positive Rate:    {metrics_base['false_positive_rate']:.4f}                {metrics_adv['false_positive_rate']:.4f}")
    print(f"False Negative Rate:    {metrics_base['false_negative_rate']:.4f}                {metrics_adv['false_negative_rate']:.4f}")
    print("=============================================================")

    # Error Analysis (False Positives and False Negatives in Advanced Model)
    error_cases = []
    for idx, (true_lbl, pred_lbl, code) in enumerate(zip(y_test, y_pred_adv, X_test_raw)):
        if true_lbl != pred_lbl:
            err_type = "False Positive" if pred_lbl == 1 else "False Negative"
            error_cases.append({
                "sample_index": idx,
                "error_type": err_type,
                "true_label": int(true_lbl),
                "predicted_label": int(pred_lbl),
                "code_snippet": code.strip()[:150] + "..."
            })

    print(f"\n[+] Error Analysis: Identified {len(error_cases)} misclassifications out of {len(y_test)} test samples.")
    for err in error_cases[:3]:
        print(f"    - Type: {err['error_type']} | Snippet: {err['code_snippet']}")

    results = {
        "baseline_model": metrics_base,
        "advanced_model": metrics_adv,
        "error_analysis": {
            "total_errors": len(error_cases),
            "false_positives": sum(1 for e in error_cases if e["error_type"] == "False Positive"),
            "false_negatives": sum(1 for e in error_cases if e["error_type"] == "False Negative"),
            "samples": error_cases
        }
    }

    with open(config.METRICS_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Saved evaluation metrics to: {config.METRICS_PATH}")

    return results

if __name__ == "__main__":
    from train import train_vulnerability_detectors
    train_res = train_vulnerability_detectors()
    evaluate_models(train_res)
