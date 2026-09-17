"""
Visualization Script for ML Security Evaluation Results.
Generates publication-quality charts for confusion matrices, ROC curves,
feature importances, and AI patch security distributions.
"""

import os
import json
import joblib
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import roc_curve, auc, confusion_matrix

import config

def set_style():
    """
    Applies clean aesthetic theme for academic charts.
    """
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
    plt.rcParams['font.family'] = 'sans-serif'
    plt.rcParams['font.size'] = 11

def plot_confusion_matrices(train_results: dict):
    """
    Plots side-by-side confusion matrix heatmaps for Baseline vs Advanced models.
    """
    set_style()
    X_test = train_results["X_test"]
    y_test = train_results["y_test"]
    baseline_model = train_results["baseline_model"]
    advanced_model = train_results["advanced_model"]

    y_pred_base = baseline_model.predict(X_test)
    y_pred_adv = advanced_model.predict(X_test)

    cm_base = confusion_matrix(y_test, y_pred_base)
    cm_adv = confusion_matrix(y_test, y_pred_adv)

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Baseline Heatmap
    sns.heatmap(cm_base, annot=True, fmt='d', cmap='Blues', ax=axes[0], cbar=False,
                xticklabels=['Secure (0)', 'Vulnerable (1)'],
                yticklabels=['Secure (0)', 'Vulnerable (1)'])
    axes[0].set_title('Baseline Model: Logistic Regression\nConfusion Matrix', fontsize=12, fontweight='bold')
    axes[0].set_xlabel('Predicted Label')
    axes[0].set_ylabel('True Label')

    # Advanced Heatmap
    sns.heatmap(cm_adv, annot=True, fmt='d', cmap='Greens', ax=axes[1], cbar=False,
                xticklabels=['Secure (0)', 'Vulnerable (1)'],
                yticklabels=['Secure (0)', 'Vulnerable (1)'])
    axes[1].set_title('Advanced Model: Random Forest\nConfusion Matrix', fontsize=12, fontweight='bold')
    axes[1].set_xlabel('Predicted Label')
    axes[1].set_ylabel('True Label')

    plt.tight_layout()
    out_path = os.path.join(config.RESULTS_DIR, "confusion_matrices.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"[+] Saved Confusion Matrices plot to: {out_path}")


def plot_roc_curves(train_results: dict):
    """
    Plots ROC curves for Baseline vs Advanced models.
    """
    set_style()
    X_test = train_results["X_test"]
    y_test = train_results["y_test"]
    baseline_model = train_results["baseline_model"]
    advanced_model = train_results["advanced_model"]

    y_prob_base = baseline_model.predict_proba(X_test)[:, 1]
    y_prob_adv = advanced_model.predict_proba(X_test)[:, 1]

    fpr_base, tpr_base, _ = roc_curve(y_test, y_prob_base)
    auc_base = auc(fpr_base, tpr_base)

    fpr_adv, tpr_adv, _ = roc_curve(y_test, y_prob_adv)
    auc_adv = auc(fpr_adv, tpr_adv)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr_base, tpr_base, color='#2b5c8f', lw=2, label=f'Baseline (Logistic) - AUC = {auc_base:.4f}')
    plt.plot(fpr_adv, tpr_adv, color='#2e7d32', lw=2.5, label=f'Advanced (Random Forest) - AUC = {auc_adv:.4f}')
    plt.plot([0, 1], [0, 1], color='gray', lw=1.5, linestyle='--')

    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate (FPR)', fontsize=12)
    plt.ylabel('True Positive Rate (Recall)', fontsize=12)
    plt.title('Receiver Operating Characteristic (ROC) Comparison', fontsize=14, fontweight='bold')
    plt.legend(loc="lower right", fontsize=11)
    plt.grid(True, linestyle=':', alpha=0.6)

    plt.tight_layout()
    out_path = os.path.join(config.RESULTS_DIR, "roc_curve.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"[+] Saved ROC Curve plot to: {out_path}")


def plot_feature_importances(train_results: dict):
    """
    Plots top 15 most influential features in the Advanced Random Forest model.
    """
    set_style()
    feature_pipeline = train_results["feature_pipeline"]
    advanced_model = train_results["advanced_model"]

    feature_names = feature_pipeline.get_feature_names()
    importances = advanced_model.feature_importances_

    # Sort top 15 features
    indices = np.argsort(importances)[::-1][:15]
    top_names = [feature_names[i] for i in indices]
    top_importances = importances[indices]

    # Clean display names
    top_names_clean = [name.replace("domain_", "Domain: ").replace("tfidf_", "Token: ") for name in top_names]

    plt.figure(figsize=(10, 6))
    palette = sns.color_palette("viridis", len(top_names_clean))
    sns.barplot(x=top_importances, y=top_names_clean, hue=top_names_clean, palette=palette, legend=False)

    plt.xlabel('Relative Feature Importance (Gini Impurity Decrease)', fontsize=12)
    plt.title('Top 15 Predictive Features for Vulnerability Detection', fontsize=14, fontweight='bold')
    plt.tight_layout()

    out_path = os.path.join(config.RESULTS_DIR, "feature_importance.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"[+] Saved Feature Importances plot to: {out_path}")


def plot_ai_patch_distribution():
    """
    Plots donut chart of AI Patch Evaluation categories (C-SEC, C-SUS, C-VUL, IC).
    """
    set_style()
    if not os.path.exists(config.AI_EVAL_RESULTS_PATH):
        return

    with open(config.AI_EVAL_RESULTS_PATH, "r") as f:
        res = json.load(f)

    summary = res["summary"]
    categories = ['C-SEC\n(Secure)', 'C-SUS\n(Suspicious)', 'C-VUL\n(Vulnerable)', 'IC\n(Incorrect)']
    counts = [summary['c_sec_count'], summary['c_sus_count'], summary['c_vul_count'], summary['ic_count']]
    colors = ['#2e7d32', '#f57c00', '#d32f2f', '#757575']

    plt.figure(figsize=(8, 7))
    plt.pie(counts, labels=categories, colors=colors, autopct='%1.1f%%', startangle=140,
            textprops={'fontsize': 12, 'fontweight': 'bold'},
            wedgeprops=dict(width=0.4, edgecolor='w', linewidth=2))

    plt.title('AI-Generated C/C++ Patch Evaluation Distribution\n(SecureVibeBench Framework)', fontsize=14, fontweight='bold')
    plt.tight_layout()

    out_path = os.path.join(config.RESULTS_DIR, "ai_patch_distribution.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"[+] Saved AI Patch Distribution plot to: {out_path}")


def generate_all_plots(train_results: dict):
    """
    Generates all visualization figures.
    """
    print("\n[+] Generating visualization plots...")
    plot_confusion_matrices(train_results)
    plot_roc_curves(train_results)
    plot_feature_importances(train_results)
    plot_ai_patch_distribution()
    print("[+] All plots successfully generated in results/")

if __name__ == "__main__":
    from train import train_vulnerability_detectors
    from ai_patch_evaluator import evaluate_ai_generated_patches
    t_res = train_vulnerability_detectors()
    evaluate_ai_generated_patches()
    generate_all_plots(t_res)
