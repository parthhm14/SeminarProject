"""
Feature Extraction Module for C/C++ Code Vulnerability Detection.
Combines TF-IDF N-gram representation with C/C++ Security Domain Lexical Features.
"""

import re
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from preprocessing import clean_code, tokenize_code, code_to_token_string
import config

class DomainSecurityFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Custom Scikit-Learn Transformer to extract domain-specific C/C++ security features.
    """
    def __init__(self):
        self.feature_names_ = [
            'dangerous_string_apis',
            'command_exec_apis',
            'memory_alloc_apis',
            'memory_free_apis',
            'pointer_deref_count',
            'has_bounds_check',
            'has_null_check',
            'free_null_reset_ratio',
            'pointer_arithmetic_count',
            'format_string_risk',
            'integer_overflow_risk',
            'assert_clamp_count',
            'raw_code_length',
            'lines_of_code',
            'cyclomatic_complexity_approx'
        ]

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        """
        Extract numerical security features from a list of code snippets.
        """
        features_list = []
        for code in X:
            if not isinstance(code, str):
                code = str(code) if code is not None else ""
            
            cleaned = clean_code(code)
            lines = [l for l in code.split('\n') if l.strip()]
            loc = len(lines)
            code_len = len(cleaned)

            # 1. Dangerous Unbounded String APIs (CWE-120/122)
            dangerous_string_apis = len(re.findall(r'\b(strcpy|strcat|sprintf|gets|vsprintf)\b', code))
            
            # 2. Command Execution APIs (CWE-78)
            command_exec_apis = len(re.findall(r'\b(system|popen|execl|execv|execvp)\b', code))
            
            # 3. Memory Allocation APIs (CWE-416/415)
            memory_alloc_apis = len(re.findall(r'\b(malloc|calloc|realloc)\b', code))
            memory_free_apis = len(re.findall(r'\bfree\b', code))
            
            # 4. Pointer Dereferences & Operations
            pointer_deref_count = len(re.findall(r'->|\*\w+', code))
            
            # 5. Bounds Check Presence (strlen, sizeof, min, max, boundary comparisons)
            bounds_check_matches = len(re.findall(r'\b(sizeof|strlen|min|max)\b|<=|>=|<|>', code))
            has_bounds_check = 1.0 if bounds_check_matches > 0 else 0.0

            # 6. NULL Check Presence (nullptr, NULL, == 0, != 0, !ptr)
            null_check_matches = len(re.findall(r'\b(NULL|nullptr)\b|==\s*0|!=\s*0|!\w+', code))
            has_null_check = 1.0 if null_check_matches > 0 else 0.0

            # 7. Safe Free (setting pointer to NULL after free)
            free_null_resets = len(re.findall(r'free\s*\([^)]+\)\s*;\s*\w+\s*=\s*(NULL|nullptr|0);', code))
            free_null_reset_ratio = (free_null_resets / memory_free_apis) if memory_free_apis > 0 else 1.0

            # 8. Pointer Arithmetic Risk (ptr + n, ptr++, ptr - n)
            pointer_arithmetic_count = len(re.findall(r'\w+\s*[\+\-]\s*\w+|\w+\+\+|\+\+\w+|\w+--|--\w+', code))

            # 9. Format String Risk (printf/sprintf with non-string literal format)
            format_string_risk = 1.0 if len(re.findall(r'\b(printf|sprintf)\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)', code)) > 0 else 0.0

            # 10. Integer Overflow Risk (arithmetic on size/len without cast or clamp)
            integer_overflow_risk = len(re.findall(r'(size|len|count|width|height)\s*[\+\*]\s*', code, re.IGNORECASE))

            # 11. Defensive Assert / Clamp Presence
            assert_clamp_count = len(re.findall(r'\b(assert|clamp|std::min|std::max)\b', code))

            # 12. Approximate Cyclomatic Complexity (count of conditional branches)
            cyclomatic_approx = 1 + len(re.findall(r'\b(if|else|while|for|switch|case|catch)\b', code))

            feat_vec = [
                dangerous_string_apis,
                command_exec_apis,
                memory_alloc_apis,
                memory_free_apis,
                pointer_deref_count,
                has_bounds_check,
                has_null_check,
                free_null_reset_ratio,
                pointer_arithmetic_count,
                format_string_risk,
                integer_overflow_risk,
                assert_clamp_count,
                code_len,
                loc,
                cyclomatic_approx
            ]
            features_list.append(feat_vec)

        return np.array(features_list, dtype=np.float64)

    def get_feature_names_out(self, input_features=None):
        return np.array(self.feature_names_)


class CodeFeaturePipeline:
    """
    Combined Vectorizer pipeline extracting TF-IDF N-grams + C/C++ Security Domain Features.
    """
    def __init__(self, max_tfidf_features=config.TFIDF_MAX_FEATURES, ngram_range=config.NGRAM_RANGE):
        self.tfidf = TfidfVectorizer(
            tokenizer=tokenize_code,
            preprocessor=clean_code,
            ngram_range=ngram_range,
            max_features=max_tfidf_features,
            token_pattern=None
        )
        self.domain_extractor = DomainSecurityFeatureExtractor()
        self.feature_names_ = []

    def fit_transform(self, X, y=None):
        tfidf_feats = self.tfidf.fit_transform(X).toarray()
        domain_feats = self.domain_extractor.fit_transform(X)
        
        # Combine TF-IDF names with domain names
        tfidf_names = [f"tfidf_{name}" for name in self.tfidf.get_feature_names_out()]
        domain_names = [f"domain_{name}" for name in self.domain_extractor.get_feature_names_out()]
        self.feature_names_ = tfidf_names + domain_names

        combined = np.hstack((tfidf_feats, domain_feats))
        return combined

    def transform(self, X):
        tfidf_feats = self.tfidf.transform(X).toarray()
        domain_feats = self.domain_extractor.transform(X)
        combined = np.hstack((tfidf_feats, domain_feats))
        return combined

    def get_feature_names(self):
        return self.feature_names_
