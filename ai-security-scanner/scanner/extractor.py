# import ast
# import re

# # ─────────────────────────────────────────
# # DANGEROUS PATTERNS TO LOOK FOR
# # ─────────────────────────────────────────

# DANGEROUS_FUNCTIONS = [
#     "eval", "exec", "compile",
#     "os.system", "subprocess.call", "subprocess.run",
#     "subprocess.Popen", "__import__"
# ]

# DANGEROUS_IMPORTS = [
#     "subprocess", "pickle", "shelve",
#     "ctypes", "socket", "pty"
# ]

# SECRET_PATTERNS = [
#     r'password\s*=\s*["\'].*["\']',
#     r'api_key\s*=\s*["\'].*["\']',
#     r'secret\s*=\s*["\'].*["\']',
#     r'token\s*=\s*["\'].*["\']',
#     r'AWS_SECRET',
#     r'private_key',
# ]

# DANGEROUS_PIPELINE_COMMANDS = [
#     "curl", "wget", "bash", "sh",
#     "nc", "netcat", "python -c",
#     "base64", "chmod +x", "eval"
# ]

# CREDENTIAL_LEAK_PATTERNS = [
#     r'echo\s+\$.*KEY',
#     r'echo\s+\$.*SECRET',
#     r'echo\s+\$.*PASSWORD',
#     r'echo\s+\$.*TOKEN',
#     r'curl.*--data.*\$',
#     r'wget.*--post-data',
# ]


# # ─────────────────────────────────────────
# # PYTHON CODE FEATURE EXTRACTOR
# # ─────────────────────────────────────────

# def extract_python_features(parse_result):
#     """
#     Takes a parsed Python file result and extracts security features.
#     """
#     features = {
#         "filepath": parse_result["filepath"],
#         "file_type": "python",
#         "dangerous_functions": [],
#         "dangerous_imports": [],
#         "hardcoded_secrets": [],
#         "network_calls": [],
#         "file_operations": [],
#         "total_functions": 0,
#         "total_lines": 0,
#     }

#     source = parse_result["source"]
#     tree = parse_result["ast_tree"]

#     # Count total lines
#     features["total_lines"] = len(source.splitlines())

#     # Walk through AST nodes
#     for node in ast.walk(tree):

#         # Count function definitions
#         if isinstance(node, ast.FunctionDef):
#             features["total_functions"] += 1

#         # Detect dangerous function calls
#         if isinstance(node, ast.Call):
#             func_name = ""

#             if isinstance(node.func, ast.Name):
#                 func_name = node.func.id

#             elif isinstance(node.func, ast.Attribute):
#                 if isinstance(node.func.value, ast.Name):
#                     func_name = f"{node.func.value.id}.{node.func.attr}"
#                 else:
#                     func_name = node.func.attr

#             if func_name in DANGEROUS_FUNCTIONS:
#                 features["dangerous_functions"].append(func_name)

#             # Detect network calls
#             if func_name in ["requests.get", "requests.post",
#                               "urllib.request.urlopen", "socket.connect"]:
#                 features["network_calls"].append(func_name)

#             # Detect file operations
#             if func_name in ["open", "os.remove", "os.unlink",
#                               "shutil.rmtree", "os.rmdir"]:
#                 features["file_operations"].append(func_name)

#         # Detect dangerous imports
#         if isinstance(node, ast.Import):
#             for alias in node.names:
#                 if alias.name in DANGEROUS_IMPORTS:
#                     features["dangerous_imports"].append(alias.name)

#         if isinstance(node, ast.ImportFrom):
#             if node.module in DANGEROUS_IMPORTS:
#                 features["dangerous_imports"].append(node.module)

#     # Detect hardcoded secrets using regex on raw source
#     for pattern in SECRET_PATTERNS:
#         matches = re.findall(pattern, source, re.IGNORECASE)
#         if matches:
#             features["hardcoded_secrets"].extend(matches)

#     return features


# # ─────────────────────────────────────────
# # PIPELINE FEATURE EXTRACTOR
# # ─────────────────────────────────────────

# def extract_pipeline_features(parse_result):
#     """
#     Takes a parsed pipeline file result and extracts security features.
#     """
#     features = {
#         "filepath": parse_result["filepath"],
#         "file_type": "pipeline",
#         "dangerous_commands": [],
#         "credential_leaks": [],
#         "external_script_execution": [],
#         "total_stages": 0,
#         "total_commands": 0,
#     }

#     stages = parse_result.get("stages", [])
#     features["total_stages"] = len(stages)

#     for stage in stages:
#         commands = stage.get("commands", [])
#         features["total_commands"] += len(commands)

#         for command in commands:
#             # Skip GitHub Actions references like [ACTION] actions/checkout@v3
#             if command.startswith("[ACTION]"):
#                 continue

#             # Detect dangerous commands
#             for dangerous in DANGEROUS_PIPELINE_COMMANDS:
#                 if dangerous in command.lower():
#                     features["dangerous_commands"].append({
#                         "stage": stage["stage"],
#                         "command": command.strip(),
#                         "trigger": dangerous
#                     })

#             # Detect credential leaks
#             for pattern in CREDENTIAL_LEAK_PATTERNS:
#                 if re.search(pattern, command, re.IGNORECASE):
#                     features["credential_leaks"].append({
#                         "stage": stage["stage"],
#                         "command": command.strip()
#                     })

#             # Detect piping external scripts (e.g. curl ... | bash)
#             if re.search(r'curl.*\|\s*(bash|sh)', command):
#                 features["external_script_execution"].append({
#                     "stage": stage["stage"],
#                     "command": command.strip()
#                 })

#     return features


# # ─────────────────────────────────────────
# # MAIN EXTRACTOR — AUTO DETECT FILE TYPE
# # ─────────────────────────────────────────

# def extract_features(parse_result):
#     """
#     Automatically calls the right extractor based on file type.
#     """
#     if parse_result.get("file_type") == "python":
#         return extract_python_features(parse_result)
#     elif parse_result.get("file_type") == "pipeline":
#         return extract_pipeline_features(parse_result)
#     else:
#         return {"error": "Unsupported file type"}


import re

DANGEROUS_PIPELINE_COMMANDS = [
    "curl", "wget", "bash", "sh", "nc", "netcat", "python -c", "base64", "chmod +x", "eval"
]

CREDENTIAL_LEAK_PATTERNS = [
    r'echo\s+\$.*KEY', r'echo\s+\$.*SECRET', r'echo\s+\$.*PASSWORD', r'echo\s+\$.*TOKEN',
    r'curl.*--data.*\$', r'wget.*--post-data',
]


def extract_pipeline_features(parse_result):
    features = {
        "filepath": parse_result["filepath"],
        "file_type": "pipeline",
        "dangerous_commands": [],
        "credential_leaks": [],
        "external_script_execution": [],
        "total_stages": 0,
        "total_commands": 0,
    }
    stages = parse_result.get("stages", [])
    features["total_stages"] = len(stages)

    for stage in stages:
        commands = stage.get("commands", [])
        features["total_commands"] += len(commands)
        for command in commands:
            if command.startswith("[ACTION]"):
                continue
            for dangerous in DANGEROUS_PIPELINE_COMMANDS:
                if dangerous in command.lower():
                    features["dangerous_commands"].append({
                        "stage": stage["stage"], "command": command.strip(), "trigger": dangerous
                    })
            for pattern in CREDENTIAL_LEAK_PATTERNS:
                if re.search(pattern, command, re.IGNORECASE):
                    features["credential_leaks"].append({"stage": stage["stage"], "command": command.strip()})
            if re.search(r'curl.*\|\s*(bash|sh)', command):
                features["external_script_execution"].append({"stage": stage["stage"], "command": command.strip()})

    return features


def extract_features(parse_result):
    if parse_result.get("file_type") == "pipeline":
        return extract_pipeline_features(parse_result)
    return {"error": "Unsupported file type"}