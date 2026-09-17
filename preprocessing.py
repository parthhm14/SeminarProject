"""
C/C++ Code Preprocessing and Normalization Module.
Provides lexing, comment removal, string normalization, and tokenization.
"""

import re

def remove_comments(code: str) -> str:
    """
    Remove single-line (//) and multi-line (/* ... */) comments from C/C++ code.
    """
    if not code:
        return ""
    # Multi-line comments
    code = re.sub(r'/\*.*?\*/', ' ', code, flags=re.DOTALL)
    # Single-line comments
    code = re.sub(r'//.*', ' ', code)
    return code

def normalize_literals(code: str) -> str:
    """
    Normalize string literals and numeric constants to abstract placeholders
    to prevent memorization of specific strings or numbers.
    """
    if not code:
        return ""
    # Normalize double-quoted string literals
    code = re.sub(r'"([^"\\]|\\.)*"', '"STR_LITERAL"', code)
    # Normalize single-quoted char literals
    code = re.sub(r"'([^'\\]|\\.)*'", "'CHAR_LITERAL'", code)
    # Normalize numeric constants (hex or dec)
    code = re.sub(r'\b0x[0-9a-fA-F]+\b', 'NUM_HEX', code)
    code = re.sub(r'\b\d+\b', 'NUM_DEC', code)
    return code

def clean_code(code: str) -> str:
    """
    Full cleaning pipeline: removes comments, normalizes literals, collapses whitespace.
    """
    if not code:
        return ""
    code = remove_comments(code)
    code = normalize_literals(code)
    # Collapse multiple whitespaces/newlines
    code = re.sub(r'\s+', ' ', code).strip()
    return code

def tokenize_code(code: str) -> list:
    """
    Tokenizes C/C++ code into meaningful code identifiers, operators, and keywords.
    """
    cleaned = clean_code(code)
    # Tokenize words, symbols, and operators
    tokens = re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b|==|!=|<=|>=|&&|\|\||->|\+\+|--|[+\-*/%<>=!&|^~]', cleaned)
    return tokens

def code_to_token_string(code: str) -> str:
    """
    Returns space-separated token sequence suitable for TF-IDF vectorization.
    """
    tokens = tokenize_code(code)
    return " ".join(tokens)
