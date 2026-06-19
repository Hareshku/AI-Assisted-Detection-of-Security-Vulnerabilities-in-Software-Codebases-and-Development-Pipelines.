# # ─────────────────────────────────────────
# # RISK SCORING ENGINE
# # Converts extracted features into a risk score
# # ─────────────────────────────────────────

# # Point weights for each type of finding
# RISK_WEIGHTS = {
#     # Python code risks
#     "dangerous_function":   15,   # e.g. eval, exec, os.system
#     "dangerous_import":     10,   # e.g. subprocess, pickle
#     "hardcoded_secret":     20,   # e.g. password = "abc123"
#     "network_call":          8,   # e.g. requests.get()
#     "file_operation":        5,   # e.g. open(), os.remove()

#     # Pipeline risks
#     "dangerous_command":    15,   # e.g. curl, wget, bash
#     "credential_leak":      25,   # e.g. echo $SECRET_KEY
#     "external_script_exec": 30,   # e.g. curl url | bash
# }

# # Risk thresholds
# RISK_LEVELS = {
#     "LOW":      (0,  30),
#     "MEDIUM":   (31, 65),
#     "HIGH":     (66, 999),
# }


# def calculate_risk_score(features):
#     """
#     Takes extracted features and returns a risk score + level.
#     """
#     score = 0
#     reasons = []

#     if features.get("file_type") == "python":

#         # Score dangerous functions
#         count = len(features.get("dangerous_functions", []))
#         if count > 0:
#             points = count * RISK_WEIGHTS["dangerous_function"]
#             score += points
#             reasons.append(f"Dangerous functions ({count} found): +{points} pts")

#         # Score dangerous imports
#         count = len(features.get("dangerous_imports", []))
#         if count > 0:
#             points = count * RISK_WEIGHTS["dangerous_import"]
#             score += points
#             reasons.append(f"Dangerous imports ({count} found): +{points} pts")

#         # Score hardcoded secrets
#         count = len(features.get("hardcoded_secrets", []))
#         if count > 0:
#             points = count * RISK_WEIGHTS["hardcoded_secret"]
#             score += points
#             reasons.append(f"Hardcoded secrets ({count} found): +{points} pts")

#         # Score network calls
#         count = len(features.get("network_calls", []))
#         if count > 0:
#             points = count * RISK_WEIGHTS["network_call"]
#             score += points
#             reasons.append(f"Network calls ({count} found): +{points} pts")

#         # Score file operations
#         count = len(features.get("file_operations", []))
#         if count > 0:
#             points = count * RISK_WEIGHTS["file_operation"]
#             score += points
#             reasons.append(f"File operations ({count} found): +{points} pts")

#     elif features.get("file_type") == "pipeline":

#         # Score dangerous commands (unique only to avoid curl+bash+sh triple count)
#         unique_commands = set()
#         for item in features.get("dangerous_commands", []):
#             unique_commands.add(item["command"])
#         count = len(unique_commands)
#         if count > 0:
#             points = count * RISK_WEIGHTS["dangerous_command"]
#             score += points
#             reasons.append(f"Dangerous commands ({count} unique): +{points} pts")

#         # Score credential leaks
#         count = len(features.get("credential_leaks", []))
#         if count > 0:
#             points = count * RISK_WEIGHTS["credential_leak"]
#             score += points
#             reasons.append(f"Credential leaks ({count} found): +{points} pts")

#         # Score external script execution
#         count = len(features.get("external_script_execution", []))
#         if count > 0:
#             points = count * RISK_WEIGHTS["external_script_exec"]
#             score += points
#             reasons.append(f"External script execution ({count} found): +{points} pts")

#     # Cap score at 100
#     score = min(score, 100)

#     # Determine risk level
#     risk_level = "LOW"
#     for level, (low, high) in RISK_LEVELS.items():
#         if low <= score <= high:
#             risk_level = level
#             break

#     return {
#         "filepath":   features.get("filepath"),
#         "file_type":  features.get("file_type"),
#         "score":      score,
#         "risk_level": risk_level,
#         "reasons":    reasons
#     }


# def get_risk_emoji(risk_level):
#     return {
#         "LOW":    "🟢",
#         "MEDIUM": "🟡",
#         "HIGH":   "🔴"
#     }.get(risk_level, "⚪")



RISK_WEIGHTS = {
    "dangerous_function":   15,
    "dangerous_import":     10,
    "hardcoded_secret":     20,
    "network_call":          8,
    "file_operation":        5,
    "dangerous_command":    15,
    "credential_leak":      25,
    "external_script_exec": 30,
}

RISK_LEVELS = {
    "LOW":      (0,  30),
    "MEDIUM":   (31, 65),
    "HIGH":     (66, 999),
}

FLOW_WEIGHTS = {
    "CREDENTIAL_THEFT_FLOW": 70,
    "BACKDOOR_FLOW":         75,
    "RESOURCE_THEFT_FLOW":   35,
}

# NEW: weight per flow_type. Unlike the categories above (which score
# isolated suspicious PATTERNS), a detected flow means a source+sink
# pair was confirmed -- i.e. evidence matching one of the paper's
# real-world attack clusters (Section 4), not just a risky keyword.
# Weighted by blast radius per the paper's examples:
#   - Credential theft (HackerBot-Claw, CodeCov, CIDER, xssfox): grants
#     attacker ongoing access to everything the credential can reach.
#   - Backdoor (XZ Utils, SolarWinds): compromises every artifact built
#     downstream, the highest-impact category in the paper's examples.
#   - Resource theft (cryptomining): wastes compute, does not grant
#     access or persist in artifacts -- lower blast radius.
FLOW_WEIGHTS = {
    "CREDENTIAL_THEFT_FLOW": 70,
    "BACKDOOR_FLOW":         75,
    "RESOURCE_THEFT_FLOW":   35,
}


def calculate_risk_score(features, flow_result=None):
    score = 0
    reasons = []

    if features.get("file_type") == "python":
        count = len(features.get("dangerous_functions", []))
        if count > 0:
            points = count * RISK_WEIGHTS["dangerous_function"]
            score += points
            reasons.append(f"Dangerous functions ({count} found): +{points} pts")

        count = len(features.get("dangerous_imports", []))
        if count > 0:
            points = count * RISK_WEIGHTS["dangerous_import"]
            score += points
            reasons.append(f"Dangerous imports ({count} found): +{points} pts")

        count = len(features.get("hardcoded_secrets", []))
        if count > 0:
            points = count * RISK_WEIGHTS["hardcoded_secret"]
            score += points
            reasons.append(f"Hardcoded secrets ({count} found): +{points} pts")

        count = len(features.get("network_calls", []))
        if count > 0:
            points = count * RISK_WEIGHTS["network_call"]
            score += points
            reasons.append(f"Network calls ({count} found): +{points} pts")

        count = len(features.get("file_operations", []))
        if count > 0:
            points = count * RISK_WEIGHTS["file_operation"]
            score += points
            reasons.append(f"File operations ({count} found): +{points} pts")

    elif features.get("file_type") == "pipeline":
        unique_commands = set()
        for item in features.get("dangerous_commands", []):
            unique_commands.add(item["command"])
        count = len(unique_commands)
        if count > 0:
            points = count * RISK_WEIGHTS["dangerous_command"]
            score += points
            reasons.append(f"Dangerous commands ({count} unique): +{points} pts")

        count = len(features.get("credential_leaks", []))
        if count > 0:
            points = count * RISK_WEIGHTS["credential_leak"]
            score += points
            reasons.append(f"Credential leaks ({count} found): +{points} pts")

        count = len(features.get("external_script_execution", []))
        if count > 0:
            points = count * RISK_WEIGHTS["external_script_exec"]
            score += points
            reasons.append(f"External script execution ({count} found): +{points} pts")

        # ── NEW: fold in paper-based flow detections ──
        if flow_result:
            for flow in flow_result.get("malicious_flows", []):
                points = FLOW_WEIGHTS.get(flow["flow_type"], 20)
                score += points
                reasons.append(
                    f"[{flow['flow_type']}] in '{flow['stage']}' stage: +{points} pts"
                )
                

    score = min(score, 100)

    risk_level = "LOW"
    for level, (low, high) in RISK_LEVELS.items():
        if low <= score <= high:
            risk_level = level
            break

    return {
        "filepath":   features.get("filepath"),
        "file_type":  features.get("file_type"),
        "score":      score,
        "risk_level": risk_level,
        "reasons":    reasons
    }


def get_risk_emoji(risk_level):
    return {
        "LOW":    "🟢",
        "MEDIUM": "🟡",
        "HIGH":   "🔴"
    }.get(risk_level, "⚪")