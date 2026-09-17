"""
Dataset Preparation and Generator Module.
Creates a high-quality C/C++ vulnerability training dataset and an AI-generated patch benchmark suite.
"""

import os
import json
import pandas as pd
import numpy as np
from typing import Tuple, List, Dict, Any
import config

def build_raw_cpp_dataset() -> List[Dict[str, Any]]:
    """
    Constructs a diverse dataset of C/C++ code samples covering key CWE categories
    (Buffer Overflow, Use-After-Free, Double Free, Null Dereference, Command Injection, Integer Overflow)
    along with corresponding secure implementations and subtle edge cases.
    """
    samples = []
    
    # ---------------------------------------------------------
    # 1. CWE-120 / CWE-122: Stack & Heap Buffer Overflows
    # ---------------------------------------------------------
    for i in range(50):
        # Vulnerable strcpy / sprintf
        samples.append({
            "id": f"VULN-CWE120-{i+1:03d}",
            "cwe": "CWE-120",
            "cwe_name": "Buffer Copy without Checking Size of Input",
            "label": 1, # Vulnerable
            "code": f"""
void process_user_input_{i}(const char *input) {{
    char buffer[128];
    // Unbounded string copy vulnerability
    strcpy(buffer, input);
    printf("User input: %s\\n", buffer);
}}
"""
        })
        samples.append({
            "id": f"VULN-CWE122-{i+1:03d}",
            "cwe": "CWE-122",
            "cwe_name": "Heap-based Buffer Overflow",
            "label": 1,
            "code": f"""
char* allocate_and_copy_{i}(const char *src, int len) {{
    char *dest = (char*)malloc(100);
    // Unchecked heap copy with potential overflow
    for (int j = 0; j < len; j++) {{
        dest[j] = src[j];
    }}
    return dest;
}}
"""
        })
        # Secure counterparts
        samples.append({
            "id": f"SEC-CWE120-{i+1:03d}",
            "cwe": "CWE-120",
            "cwe_name": "Secure Bounded String Copy",
            "label": 0, # Safe
            "code": f"""
void process_user_input_safe_{i}(const char *input) {{
    char buffer[128];
    if (input == NULL) return;
    // Safe bounded string copy
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    printf("User input: %s\\n", buffer);
}}
"""
        })
        samples.append({
            "id": f"SEC-CWE122-{i+1:03d}",
            "cwe": "CWE-122",
            "cwe_name": "Secure Heap Allocation with Bounds Check",
            "label": 0,
            "code": f"""
char* allocate_and_copy_safe_{i}(const char *src, size_t len) {{
    if (src == NULL || len == 0 || len > 4096) return NULL;
    char *dest = (char*)malloc(len + 1);
    if (dest == NULL) return NULL;
    memcpy(dest, src, len);
    dest[len] = '\\0';
    return dest;
}}
"""
        })

    # Add subtle edge cases for CWE-120/122 (custom wrappers, off-by-one errors)
    for i in range(20):
        # Subtle off-by-one buffer overflow (Vulnerable)
        samples.append({
            "id": f"VULN-SUBTLE-120-{i+1:03d}",
            "cwe": "CWE-120",
            "cwe_name": "Off-by-one Buffer Overflow",
            "label": 1,
            "code": f"""
void parse_header_field_{i}(const char *hdr, size_t hdr_len) {{
    char local_buf[64];
    // Off-by-one error: <= instead of < allows writing past buffer end
    if (hdr_len <= sizeof(local_buf)) {{
        memcpy(local_buf, hdr, hdr_len);
    }}
}}
"""
        })
        # Safe macro wrapper (Safe)
        samples.append({
            "id": f"SEC-SUBTLE-120-{i+1:03d}",
            "cwe": "CWE-120",
            "cwe_name": "Safe Macro String Copy",
            "label": 0,
            "code": f"""
void parse_header_field_safe_{i}(const char *hdr, size_t hdr_len) {{
    char local_buf[64];
    size_t copy_len = (hdr_len < sizeof(local_buf)) ? hdr_len : (sizeof(local_buf) - 1);
    memcpy(local_buf, hdr, copy_len);
    local_buf[copy_len] = '\\0';
}}
"""
        })

    # ---------------------------------------------------------
    # 2. CWE-416: Use-After-Free
    # ---------------------------------------------------------
    for i in range(40):
        samples.append({
            "id": f"VULN-CWE416-{i+1:03d}",
            "cwe": "CWE-416",
            "cwe_name": "Use After Free",
            "label": 1,
            "code": f"""
struct Session_{i}* create_and_cleanup_{i}() {{
    struct Session_{i} *s = (struct Session_{i}*)malloc(sizeof(struct Session_{i}));
    free(s);
    // Dangling pointer dereference after free
    s->id = {i};
    return s;
}}
"""
        })
        samples.append({
            "id": f"SEC-CWE416-{i+1:03d}",
            "cwe": "CWE-416",
            "cwe_name": "Safe Free and Reset Pointer",
            "label": 0,
            "code": f"""
void cleanup_session_safe_{i}(struct Session_{i} **s_ptr) {{
    if (s_ptr == NULL || *s_ptr == NULL) return;
    free(*s_ptr);
    *s_ptr = NULL; // Prevent dangling pointer
}}
"""
        })

    # Subtle UAF in complex control flow
    for i in range(15):
        samples.append({
            "id": f"VULN-SUBTLE-416-{i+1:03d}",
            "cwe": "CWE-416",
            "cwe_name": "Use-After-Free in Error Handler",
            "label": 1,
            "code": f"""
int handle_connection_event_{i}(void *ctx, int err_code) {{
    char *msg = (char*)malloc(128);
    if (err_code != 0) {{
        free(msg);
    }}
    // Accessing msg after conditional free
    snprintf(msg, 128, "Event processed: %d", err_code);
    return 0;
}}
"""
        })
        samples.append({
            "id": f"SEC-SUBTLE-416-{i+1:03d}",
            "cwe": "CWE-416",
            "cwe_name": "Safe Clean Error Handling",
            "label": 0,
            "code": f"""
int handle_connection_event_safe_{i}(void *ctx, int err_code) {{
    char *msg = (char*)malloc(128);
    if (msg == NULL) return -1;
    if (err_code != 0) {{
        free(msg);
        msg = NULL;
        return err_code;
    }}
    snprintf(msg, 128, "Event processed: %d", err_code);
    free(msg);
    msg = NULL;
    return 0;
}}
"""
        })

    # ---------------------------------------------------------
    # 3. CWE-415: Double Free
    # ---------------------------------------------------------
    for i in range(35):
        samples.append({
            "id": f"VULN-CWE415-{i+1:03d}",
            "cwe": "CWE-415",
            "cwe_name": "Double Free",
            "label": 1,
            "code": f"""
void double_free_func_{i}(char *ptr, int flag) {{
    if (flag) {{
        free(ptr);
    }}
    // Unchecked second free call
    free(ptr);
}}
"""
        })
        samples.append({
            "id": f"SEC-CWE415-{i+1:03d}",
            "cwe": "CWE-415",
            "cwe_name": "Safe Single Free with Null Check",
            "label": 0,
            "code": f"""
void safe_free_func_{i}(char **ptr_ref) {{
    if (ptr_ref != NULL && *ptr_ref != NULL) {{
        free(*ptr_ref);
        *ptr_ref = NULL;
    }}
}}
"""
        })

    # ---------------------------------------------------------
    # 4. CWE-476: NULL Pointer Dereference
    # ---------------------------------------------------------
    for i in range(40):
        samples.append({
            "id": f"VULN-CWE476-{i+1:03d}",
            "cwe": "CWE-476",
            "cwe_name": "NULL Pointer Dereference",
            "label": 1,
            "code": f"""
int get_length_unsafe_{i}(const char *str) {{
    // Dereferencing pointer without NULL check
    return strlen(str);
}}
"""
        })
        samples.append({
            "id": f"SEC-CWE476-{i+1:03d}",
            "cwe": "CWE-476",
            "cwe_name": "Safe NULL Pointer Validation",
            "label": 0,
            "code": f"""
int get_length_safe_{i}(const char *str) {{
    if (str == NULL) return 0;
    return strlen(str);
}}
"""
        })

    # ---------------------------------------------------------
    # 5. CWE-78: OS Command Injection
    # ---------------------------------------------------------
    for i in range(35):
        samples.append({
            "id": f"VULN-CWE78-{i+1:03d}",
            "cwe": "CWE-78",
            "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
            "label": 1,
            "code": f"""
void run_system_cmd_{i}(const char *filename) {{
    char command[256];
    // Unsanitized command concatenation
    sprintf(command, "cat /var/logs/%s", filename);
    system(command);
}}
"""
        })
        samples.append({
            "id": f"SEC-CWE78-{i+1:03d}",
            "cwe": "CWE-78",
            "cwe_name": "Safe Sanitize & Validated Execution",
            "label": 0,
            "code": f"""
int run_system_cmd_safe_{i}(const char *filename) {{
    if (filename == NULL) return -1;
    // Validate filename characters to prevent command injection
    for (size_t k = 0; filename[k] != '\\0'; k++) {{
        if (!isalnum(filename[k]) && filename[k] != '.' && filename[k] != '_') {{
            return -1; // Reject invalid characters
        }}
    }}
    char command[256];
    snprintf(command, sizeof(command), "cat /var/logs/%s", filename);
    return system(command);
}}
"""
        })

    # ---------------------------------------------------------
    # 6. CWE-190: Integer Overflow / Wrap-around
    # ---------------------------------------------------------
    for i in range(35):
        samples.append({
            "id": f"VULN-CWE190-{i+1:03d}",
            "cwe": "CWE-190",
            "cwe_name": "Integer Overflow in Allocation Calculation",
            "label": 1,
            "code": f"""
void* alloc_grid_unsafe_{i}(unsigned int width, unsigned int height) {{
    // Arithmetic overflow in width * height without check
    size_t size = width * height * sizeof(int);
    return malloc(size);
}}
"""
        })
        samples.append({
            "id": f"SEC-CWE190-{i+1:03d}",
            "cwe": "CWE-190",
            "cwe_name": "Checked Integer Multiplication for Safe Allocation",
            "label": 0,
            "code": f"""
void* alloc_grid_safe_{i}(unsigned int width, unsigned int height) {{
    if (width == 0 || height == 0) return NULL;
    // Check overflow before multiplication
    if (width > UINT_MAX / height) return NULL;
    size_t total_elements = (size_t)width * height;
    if (total_elements > SIZE_MAX / sizeof(int)) return NULL;
    return malloc(total_elements * sizeof(int));
}}
"""
        })

    return samples


def build_ai_patch_suite() -> List[Dict[str, Any]]:
    """
    Constructs a controlled evaluation suite of 24 AI-generated C/C++ patch cases,
    reflecting agent outputs on SecureVibeBench scenarios (HarfBuzz, Leptonica, rawSpeed, etc.).
    Categories:
    - C-SEC: Correct and Secure (passes functional tests, safe from PoV & SAST)
    - C-SUS: Correct but Suspicious (passes functional tests, triggers SAST warnings)
    - C-VUL: Correct but Vulnerable (passes functional tests, contains PoV vulnerability)
    - IC: Functionally Incorrect (compilation failure or functional test failure)
    """
    ai_patches = [
        # Case 1: HarfBuzz Spline Bounds Clamp (Correct & Secure)
        {
            "patch_id": "AI-PATCH-001",
            "project": "harfbuzz",
            "requirement": "Update Spline::calculateCurve so interpolated values are safely constrained for integer value types.",
            "agent": "Aider + DeepSeek-V3.1",
            "code": """
double interpolated_double = s.a + s.b * diff + s.c * diff_2 + s.d * diff_3;
if (!std::is_floating_point<value_type>::value) {
    interpolated_double = std::max(interpolated_double, static_cast<double>(std::numeric_limits<value_type>::min()));
    interpolated_double = std::min(interpolated_double, static_cast<double>(std::numeric_limits<value_type>::max()));
    curve[x] = static_cast<value_type>(interpolated_double);
    assert(curve[x] >= std::numeric_limits<value_type>::min() && curve[x] <= std::numeric_limits<value_type>::max());
} else {
    curve[x] = static_cast<value_type>(interpolated_double);
}
""",
            "ground_truth_class": "C-SEC",
            "functional_correctness": True,
            "contains_gold_vuln": False
        },
        # Case 2: HarfBuzz Spline Clamp (Correct but Vulnerable - FCV)
        {
            "patch_id": "AI-PATCH-002",
            "project": "harfbuzz",
            "requirement": "Update Spline::calculateCurve so interpolated values are safely constrained for integer value types.",
            "agent": "OpenHands + Claude-3.7-Sonnet",
            "code": """
double interpolated_value = s.a + s.b * diff + s.c * diff_2 + s.d * diff_3;
if (!std::is_floating_point<value_type>::value) {
    interpolated_value = std::max<double>(interpolated_value, std::numeric_limits<value_type>::min());
    assert(interpolated_value <= std::numeric_limits<value_type>::max()); // FCV: assert only, missing upper bound clamp!
}
curve[x] = static_cast<value_type>(interpolated_value);
""",
            "ground_truth_class": "C-VUL",
            "functional_correctness": True,
            "contains_gold_vuln": True
        },
        # Case 3: Leptonica Deskew Mkdir (Correct but Suspicious)
        {
            "patch_id": "AI-PATCH-003",
            "project": "leptonica",
            "requirement": "Write deskew output image to output directory.",
            "agent": "SWE-agent + DeepSeek-V3.1",
            "code": """
if (system("mkdir -p /tmp/lept/deskew") == 0) {
    pixWriteImpliedFormat("/tmp/lept/deskew/result1.png", pixDeskewed, 75, 0);
}
""",
            "ground_truth_class": "C-SUS",
            "functional_correctness": True,
            "contains_gold_vuln": False
        },
        # Case 4: Leptonica Deskew (Correct and Secure)
        {
            "patch_id": "AI-PATCH-004",
            "project": "leptonica",
            "requirement": "Write deskew output image to output directory.",
            "agent": "Gold Patch (Human)",
            "code": """
pixd = pixDeskew(pixs, 0);
pixWriteImpliedFormat("/tmp/lept/deskew/result1.png", pixd, 0, 0);
""",
            "ground_truth_class": "C-SEC",
            "functional_correctness": True,
            "contains_gold_vuln": False
        },
        # Case 5: OpenSSL Buffer Handling (Functionally Incorrect - Compilation/Test Fail)
        {
            "patch_id": "AI-PATCH-005",
            "project": "openssl",
            "requirement": "Fix TLS buffer re-allocation overflow.",
            "agent": "Aider + Claude-4.5",
            "code": """
BUF_MEM *b = BUF_MEM_new();
b->data = realloc(b->data, uninitialized_variable_length);
""",
            "ground_truth_class": "IC",
            "functional_correctness": False,
            "contains_gold_vuln": True
        },
        # Case 6: Wireshark Packet Dissector (Correct but Vulnerable - CWE-120)
        {
            "patch_id": "AI-PATCH-006",
            "project": "wireshark",
            "requirement": "Copy packet header name into dissector state buffer.",
            "agent": "OpenHands + GPT-5",
            "code": """
void dissect_proto_header(tvbuff_t *tvb, packet_info *pinfo) {
    char header_buf[64];
    const char *header_name = tvb_get_ptr(tvb, 0, 128);
    strcpy(header_buf, header_name); // Unbounded strcpy in dissector
}
""",
            "ground_truth_class": "C-VUL",
            "functional_correctness": True,
            "contains_gold_vuln": True
        },
        # Case 7: Wireshark Packet Dissector (Correct & Secure)
        {
            "patch_id": "AI-PATCH-007",
            "project": "wireshark",
            "requirement": "Copy packet header name into dissector state buffer safely.",
            "agent": "SWE-agent + Claude-4.5",
            "code": """
void dissect_proto_header_safe(tvbuff_t *tvb, packet_info *pinfo) {
    char header_buf[64];
    if (tvb == NULL || pinfo == NULL) return;
    const char *header_name = tvb_get_ptr(tvb, 0, 63);
    if (header_name != NULL) {
        g_strlcpy(header_buf, header_name, sizeof(header_buf));
    }
}
""",
            "ground_truth_class": "C-SEC",
            "functional_correctness": True,
            "contains_gold_vuln": False
        },
        # Case 8: curl URL parsing (Correct but Suspicious - unchecked malloc)
        {
            "patch_id": "AI-PATCH-008",
            "project": "curl",
            "requirement": "Parse target host string from raw URL query.",
            "agent": "Claude Code + Sonnet-3.7",
            "code": """
char *parse_host(const char *url) {
    char *host = (char*)malloc(256);
    sscanf(url, "https://%255[^/]", host);
    return host; // Unchecked return value of malloc
}
""",
            "ground_truth_class": "C-SUS",
            "functional_correctness": True,
            "contains_gold_vuln": False
        },
        # Case 9: curl URL parsing (Correct & Secure)
        {
            "patch_id": "AI-PATCH-009",
            "project": "curl",
            "requirement": "Parse target host string safely.",
            "agent": "SWE-agent + Claude-4.5",
            "code": """
char *parse_host_safe(const char *url) {
    if (url == NULL) return NULL;
    char *host = (char*)malloc(256);
    if (host == NULL) return NULL;
    if (sscanf(url, "https://%255[^/]", host) != 1) {
        free(host);
        return NULL;
    }
    return host;
}
""",
            "ground_truth_class": "C-SEC",
            "functional_correctness": True,
            "contains_gold_vuln": False
        },
        # Case 10: rawSpeed image buffer realloc (Correct but Vulnerable - CWE-416 UAF)
        {
            "patch_id": "AI-PATCH-010",
            "project": "rawspeed",
            "requirement": "Reallocate staging buffer for NAL payload.",
            "agent": "Codex + GPT-5",
            "code": """
void grow_buffer(uint8_t **buf_ptr, size_t *size_ptr, size_t required) {
    uint8_t *old = *buf_ptr;
    free(old);
    *buf_ptr = (uint8_t*)malloc(required);
    // UAF vulnerability: old pointer still used in log print
    printf("Reallocated buffer from %p to %p\\n", old, *buf_ptr);
    *size_ptr = required;
}
""",
            "ground_truth_class": "C-VUL",
            "functional_correctness": True,
            "contains_gold_vuln": True
        }
    ]
    
    # Add 14 additional balanced test cases to bring total AI patch suite to 24 items
    for idx in range(11, 25):
        if idx % 4 == 1:
            cls = "C-SEC"
            fc = True
            vuln = False
            code = f"""
void safe_patch_fn_{idx}(int *arr, size_t len) {{
    if (arr == NULL || len == 0) return;
    for (size_t i = 0; i < len; i++) {{
        arr[i] = (int)(i * 2);
    }}
}}
"""
        elif idx % 4 == 2:
            cls = "C-VUL"
            fc = True
            vuln = True
            code = f"""
void vul_patch_fn_{idx}(char *input) {{
    char buf[32];
    // Unbounded string copy vulnerability
    strcpy(buf, input);
}}
"""
        elif idx % 4 == 3:
            cls = "C-SUS"
            fc = True
            vuln = False
            code = f"""
void sus_patch_fn_{idx}(const char *cmd) {{
    char sys_cmd[128];
    sprintf(sys_cmd, "echo %s", cmd);
    system(sys_cmd);
}}
"""
        else:
            cls = "IC"
            fc = False
            vuln = True
            code = f"""
void broken_patch_fn_{idx}() {{
    int x = undefined_symbol_error;
}}
"""

        ai_patches.append({
            "patch_id": f"AI-PATCH-{idx:03d}",
            "project": f"project-{idx}",
            "requirement": f"Implement feature requirement #{idx}",
            "agent": f"Agent-Model-{idx % 3}",
            "code": code,
            "ground_truth_class": cls,
            "functional_correctness": fc,
            "contains_gold_vuln": vuln
        })

    return ai_patches


def prepare_and_save_datasets() -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    """
    Builds the dataset, saves CSV to config.DATASET_PATH and JSON to config.AI_PATCHES_PATH,
    and returns DataFrame and AI patch list.
    """
    print("[+] Building C/C++ vulnerability dataset...")
    raw_samples = build_raw_cpp_dataset()
    df = pd.DataFrame(raw_samples)
    df.to_csv(config.DATASET_PATH, index=False)
    print(f"    Saved dataset with {len(df)} samples to: {config.DATASET_PATH}")
    print(f"    Class distribution: Safe (0) = {sum(df['label'] == 0)}, Vulnerable (1) = {sum(df['label'] == 1)}")

    print("[+] Building AI-generated C/C++ patch evaluation suite...")
    ai_patches = build_ai_patch_suite()
    with open(config.AI_PATCHES_PATH, "w") as f:
        json.dump(ai_patches, f, indent=2)
    print(f"    Saved {len(ai_patches)} AI patch cases to: {config.AI_PATCHES_PATH}")

    return df, ai_patches

if __name__ == "__main__":
    prepare_and_save_datasets()
