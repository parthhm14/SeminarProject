# ML-Assisted Security Evaluation of AI-Generated C/C++ Code

**Author**: Parth Mundra (Roll No: 24CSE1035)  
**Programme**: B.Tech Computer Science and Engineering (3rd Year)  
**Institute**: National Institute of Technology (NIT) Goa  
**Seminar Topic**: Security Evaluation of AI-based Code Agents  

---

## 1. Context & Motivation

Large Language Models (LLMs) and autonomous code agents (such as SWE-agent, OpenHands, Aider, and Claude Code) are increasingly used to generate and patch software code. However, existing benchmarks primarily evaluate code agents based on **functional correctness**—whether the generated patch passes unit test suites. 

Recent research presented at **ACL 2026** highlights a major security risk:
1. **Paper 1: FCV-Attack** (*Peng et al., ACL 2026*) shows that AI agents frequently generate **Functionally Correct yet Vulnerable (FCV)** patches—code that passes all unit tests but contains critical CWE security vulnerabilities.
2. **Paper 2: SecureVibeBench** (*Chen et al., ACL 2026*) establishes a multi-oracle benchmark based on real-world Vulnerability-Introducing Commits (VIC) across 105 C/C++ repository tasks, demonstrating that state-of-the-art code agents achieve only **23.8%** secure and correct patch generation (`C-SEC`).

This project implements an **ML-assisted security evaluation prototype** designed to audit C/C++ source code and AI-generated code patches, detecting latent security vulnerabilities before code is merged into production.

---

## 2. Project Architecture & Components

The codebase is structured cleanly into reproducible Python modules:

```
project.parth/
├── config.py                 # Central configurations, hyperparameters, and file paths
├── dataset.py                # Generates/loads C/C++ vulnerability dataset & AI patch test suite
├── preprocessing.py          # C/C++ lexer, comment/literal cleaner, and tokenization
├── features.py               # Hybrid TF-IDF N-gram + C/C++ Domain Security Feature Extractor
├── sast_engine.py            # Rule-based C/C++ SAST pattern scanner (emulating Semgrep rules)
├── train.py                  # Trains Baseline (Logistic Regression) & Advanced (Random Forest) models
├── evaluate.py               # Metric evaluation (Accuracy, Precision, Recall, F1, FPR, FNR, ROC-AUC)
├── ai_patch_evaluator.py     # Evaluates AI patches against C-SEC, C-SUS, C-VUL, IC categories
├── visualize.py              # Generates publication-quality charts in results/
├── main.py                   # Master pipeline orchestration script
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

---

## 3. Machine Learning Methodology

### Feature Representation
We extract a hybrid feature vector combining lexical token n-grams with 15 domain-specific C/C++ security features:
- **Lexical Tokens**: TF-IDF (1,3)-grams of cleaned C/C++ source code.
- **Domain Security Features**:
  1. Count of dangerous unbounded string APIs (`strcpy`, `strcat`, `sprintf`, `gets`)
  2. Count of command execution APIs (`system`, `popen`, `exec*`)
  3. Count of memory allocation and free operations (`malloc`, `calloc`, `realloc`, `free`)
  4. Pointer dereference operations (`->`, `*ptr`)
  5. Presence of array bounds checks (`strlen`, `sizeof`, boundary comparisons)
  6. Presence of NULL pointer validation checks
  7. Ratio of pointer resets after `free()` (`ptr = NULL`)
  8. Pointer arithmetic counts (`ptr + n`, `ptr++`)
  9. Format string vulnerability risk indicators
  10. Integer overflow risk indicators on length parameters
  11. Cyclomatic complexity approximations

### Evaluated Models
1. **Baseline Model**: Logistic Regression (`C=1.0`, balanced class weighting).
2. **Advanced Model**: Random Forest Classifier (`n_estimators=150`, `max_depth=15`, balanced weighting).

---

## 4. SecureVibeBench Evaluation Categories

Each evaluated AI patch is categorized into one of four mutually exclusive classes:
- **`C-SEC` (Correct and Secure)**: Pass functional tests, free from gold vulnerability and SAST warnings.
- **`C-SUS` (Correct but Suspicious)**: Pass functional tests, free from gold vulnerability, but flagged by SAST rule scanner.
- **`C-VUL` (Correct but Vulnerable)**: Pass functional tests, but contain latent CWE vulnerabilities (FCV patch).
- **`IC` (Functionally Incorrect)**: Fail compilation or functional test cases.

---

## 5. Execution Instructions

### Prerequisites
Install Python 3.8+ and required dependencies:

```bash
pip install -r requirements.txt
```

### Running the End-to-End Pipeline
To run the complete data generation, training, evaluation, AI patch inference, and figure plotting pipeline:

```bash
python main.py
```

### Outputs Generated
- **`models/`**: Saved model binaries (`baseline_logistic_regression.joblib`, `advanced_random_forest.joblib`, `feature_extractor.joblib`).
- **`results/`**: 
  - `evaluation_metrics.json`: Detailed classification metrics.
  - `ai_patch_evaluation.json`: AI patch evaluation matrix.
  - `confusion_matrices.png`: Confusion matrix heatmaps.
  - `roc_curve.png`: ROC Curves for baseline vs. advanced model.
  - `feature_importance.png`: Top 15 predictive security features.
  - `ai_patch_distribution.png`: SecureVibeBench category distribution chart.

---

## 6. Security & Ethical Considerations

This project is strictly defensive and academic. It provides static auditing tools to detect vulnerabilities in code generated by AI models or human developers. It does not contain exploit payloads, automated attack runners, or malicious automation.
