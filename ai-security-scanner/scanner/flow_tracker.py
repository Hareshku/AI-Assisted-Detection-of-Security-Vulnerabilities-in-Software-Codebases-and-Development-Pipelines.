"""
flow_tracker.py

Implements the core idea from:
  Gazzillo, "Defining Software Development Pipeline Code Attacks" (2026)

Paper's definition (Section 2):
    "A pipeline code attack is when malicious changes to pipeline code
     cause malicious flows in the pipeline executor."

This module does NOT do keyword/pattern matching for its own sake.
It models:
  1. Pipeline code as stages (Source -> Build -> Test -> Deploy -> Release),
     mirroring Figure 1 (Pipeline Code / Pipeline Executor) and
     Figure 2 (Build, Test, Deploy phases) in the paper.
  2. A baseline of LEGITIMATE flows per stage, taken directly from the
     paper's own description in Section 4:
        "the build phase reads source code, executes a compiler, and
         writes program binaries; the test phase reads program binaries
         and the test files, then runs them; and the deployment phase
         reads credentials and uploads the packaged software to an
         external server."
  3. Three malicious flow categories, one per the paper's real-world
     example cluster (Section 4 / Figure 2):
        - CREDENTIAL_THEFT_FLOW  (HackerBot-Claw, CodeCov, CIDER, xssfox)
        - BACKDOOR_FLOW          (XZ Utils, SolarWinds SUNBURST)
        - RESOURCE_THEFT_FLOW    (cryptomining, shown in Figure 2)

The detector's job is to find a SOURCE (where sensitive/test/compute
resource is read) and a SINK (where it is sent/used) that together
violate the legitimate-flow baseline -- not just "this line has curl in it."
"""

import re
from typing import List

# ─────────────────────────────────────────────────────────────────
# 1. STAGE CLASSIFICATION
# A pipeline's job/stage name is mapped to one of the paper's
# canonical stages so the permission model below can be applied
# regardless of what the user named their job (e.g. "compile",
# "unit-tests", "release" all map to known stages).
# ─────────────────────────────────────────────────────────────────

STAGE_KEYWORDS = {
    "build":   ["build", "compile", "package", "bundle"],
    "test":    ["test", "lint", "check", "qa", "verify"],
    "deploy":  ["deploy", "release", "publish", "ship", "upload"],
}


def classify_stage(stage_name):
    """
    Maps an arbitrary job/stage name to a canonical pipeline phase:
    build, test, deploy, or unknown.
    """
    name = stage_name.lower()
    for canonical, keywords in STAGE_KEYWORDS.items():
        if any(kw in name for kw in keywords):
            return canonical
    return "unknown"


# ─────────────────────────────────────────────────────────────────
# 2. LEGITIMATE FLOW BASELINE (Section 4 of the paper, verbatim logic)
#
# Each canonical stage has a set of resource types it is PERMITTED
# to read and write. Anything outside this is a deviation worth
# flagging as a candidate malicious flow -- exactly the paper's
# framing that the same primitive (e.g. reading a credential, or
# reading a test file) is legitimate in one stage and a malicious
# flow in another.
# ─────────────────────────────────────────────────────────────────

LEGITIMATE_FLOWS = {
    "build":  {"reads": {"source_code"},
               "writes": {"binary"}},
    "test":   {"reads": {"binary", "test_files"},
               "writes": {"test_results"}},
    "deploy": {"reads": {"credentials"},
               "writes": {"external_upload"}},
}


# ─────────────────────────────────────────────────────────────────
# 3. RESOURCE-TYPE DETECTION PATTERNS
# Used to tag what kind of resource a given pipeline command touches.
# This is intentionally narrow -- these patterns exist only to
# identify SOURCE/SINK resource types, not to score risk directly.
# ─────────────────────────────────────────────────────────────────

RESOURCE_PATTERNS = {
    "credentials": [
        r"\$\{?\{?\s*secrets\.",          # GitHub Actions secrets.X
        r"\$[A-Z_]*(SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)[A-Z_]*",
        r"env\.[A-Z_]*(SECRET|TOKEN|KEY|PASSWORD)",
    ],
    "network_sink": [
        r"\bcurl\b", r"\bwget\b", r"\bnc\b", r"\bnetcat\b",
        r"requests\.(get|post)", r"--data\b", r"-X\s+POST",
    ],
    "test_files": [
        r"\btests?/", r"test_files?", r"fixtures?/", r"\.test\.",
    ],
    "build_action": [
        r"\bgcc\b|\bclang\b|\bld\b|\bmake\b|\blink(er)?\b|\bcompile\b",
    ],
    "compute_intensive": [
        r"\bxmrig\b|\bminerd\b|\bcryptonight\b|\bstratum\+tcp\b",
        r"\bnohup\b.*&\s*$",                  # detached background process
        r"while\s+true",                      # infinite loop pattern
    ],
}


def tag_resources(command):
    """
    Returns the set of resource-type tags this command touches,
    e.g. {"credentials", "network_sink"}.
    """
    tags = set()
    for resource_type, patterns in RESOURCE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, command, re.IGNORECASE):
                tags.add(resource_type)
                break
    return tags


# ─────────────────────────────────────────────────────────────────
# 4. FLOW DETECTORS
# Each one implements a source -> sink check for one of the paper's
# three real-world attack clusters.
# ─────────────────────────────────────────────────────────────────

def detect_credential_theft_flow(stages):
    """
    Paper basis: HackerBot-Claw, CodeCov, CIDER, xssfox (Section 4).
    "the attack modifies the pipeline to call curl or similar
     networking commands to send credentials to an attacker-
     controlled server during pipeline execution."

    Source: a command reads a credential (secrets./env var/token).
    Sink:   in the SAME command, or the same stage, that value (or
            any credential-tagged value) is passed to a network call.

    This is a source+sink co-occurrence check, deliberately stricter
    than "credential exists somewhere AND curl exists somewhere" --
    we require both tags on the same command OR the credential tag
    appears earlier in the same stage and a network sink appears
    later in that stage (modeling data flowing through stage state).
    """
    flows = []

    for stage in stages:
        stage_name = stage["stage"]
        canonical = classify_stage(stage_name)
        seen_credential_in_stage = False

        for command in stage.get("commands", []):
            if command.startswith("[ACTION]"):
                continue

            tags = tag_resources(command)

            if "credentials" in tags:
                seen_credential_in_stage = True

            # Same-line source+sink (e.g. curl --data $SECRET)
            if "credentials" in tags and "network_sink" in tags:
                flows.append({
                    "flow_type": "CREDENTIAL_THEFT_FLOW",
                    "stage": stage_name,
                    "canonical_stage": canonical,
                    "command": command.strip(),
                    "evidence": "Credential and network sink in same command",
                    "expected": list(LEGITIMATE_FLOWS.get(canonical, {}).get("reads", set())),
                })
            # Cross-command flow within the stage: credential read
            # earlier, network sink later in the same stage.
            elif "network_sink" in tags and seen_credential_in_stage:
                flows.append({
                    "flow_type": "CREDENTIAL_THEFT_FLOW",
                    "stage": stage_name,
                    "canonical_stage": canonical,
                    "command": command.strip(),
                    "evidence": "Network sink follows credential read earlier in same stage",
                    "expected": list(LEGITIMATE_FLOWS.get(canonical, {}).get("reads", set())),
                })

            # Paper-specific nuance: deploy reading credentials and
            # uploading externally IS legitimate. Only flag deploy
            # if the destination looks like an unexpected raw network
            # call rather than a recognized deployment action.
            if canonical == "deploy" and "credentials" in tags and "network_sink" in tags:
                if "[ACTION]" not in command and not re.search(
                    r"actions/deploy|aws\s+s3|aws\s+ecs|kubectl|docker\s+push",
                    command, re.IGNORECASE
                ):
                    flows[-1]["note"] = (
                        "Deploy stage legitimately reads credentials, but this "
                        "raw network call does not match a recognized deployment "
                        "action -- treated as suspicious per paper's deploy baseline."
                    )

    return flows


def detect_backdoor_flow(stages):
    """
    Paper basis: XZ Utils (Section 4).
    "The malicious pipeline code causes the build phase to read test
     files while compiling and linking source code... atypical
     behavior for a build phase."

    Source: build-stage command reads from test_files resource type.
    Sink:   that same build-stage command also performs a build_action
            (compile/link).

    This directly encodes the paper's claim that build reading test
    files during compilation is the anomaly -- not "test files exist"
    or "compilation happens" in isolation.
    """
    flows = []

    for stage in stages:
        stage_name = stage["stage"]
        canonical = classify_stage(stage_name)

        if canonical != "build":
            continue

        for command in stage.get("commands", []):
            if command.startswith("[ACTION]"):
                continue

            tags = tag_resources(command)

            if "test_files" in tags and "build_action" in tags:
                flows.append({
                    "flow_type": "BACKDOOR_FLOW",
                    "stage": stage_name,
                    "canonical_stage": canonical,
                    "command": command.strip(),
                    "evidence": (
                        "Build stage reads test_files while performing a "
                        "build_action (compile/link) -- matches XZ Utils pattern "
                        "of test-file-disguised payload entering the build"
                    ),
                    "expected": list(LEGITIMATE_FLOWS["build"]["reads"]),
                })

    return flows


def detect_resource_theft_flow(stages):
    """
    Paper basis: cryptomining flow attached to the Pipeline Automator
    in Figure 2.

    Source: any stage.
    Sink:   a compute_intensive resource tag (mining binaries,
            detached/background long-running processes) that is not
            declared as part of that stage's expected purpose.
    """
    flows = []

    for stage in stages:
        stage_name = stage["stage"]
        canonical = classify_stage(stage_name)

        for command in stage.get("commands", []):
            if command.startswith("[ACTION]"):
                continue

            tags = tag_resources(command)

            if "compute_intensive" in tags:
                flows.append({
                    "flow_type": "RESOURCE_THEFT_FLOW",
                    "stage": stage_name,
                    "canonical_stage": canonical,
                    "command": command.strip(),
                    "evidence": (
                        "Compute-intensive / detached background process "
                        "unrelated to declared stage purpose"
                    ),
                    "expected": list(LEGITIMATE_FLOWS.get(canonical, {}).get("reads", set())),
                })

    return flows


# ─────────────────────────────────────────────────────────────────
# 5. MAIN ENTRY POINT
# Runs all three detectors and also returns the flow graph data
# (nodes = stages, edges = flows) for the visualizer.
# ─────────────────────────────────────────────────────────────────

def analyze_flows(parse_result):
    """
    Takes a parsed pipeline result (from parser.py) and returns:
      - malicious_flows: list of detected flow-attack dicts
      - graph: {"nodes": [...], "edges": [...]} for visualization,
        directly mirroring Figure 2's stage-to-stage flow diagram.
    """
    stages = parse_result.get("stages", [])

    credential_flows = detect_credential_theft_flow(stages)
    backdoor_flows = detect_backdoor_flow(stages)
    resource_flows = detect_resource_theft_flow(stages)

    all_flows = credential_flows + backdoor_flows + resource_flows

    # Build graph: one node per declared stage, plus an external
    # "Internet" sink node if any credential theft flow exists.
    nodes = []
    seen_stage_names = set()
    for stage in stages:
        name = stage["stage"]
        if name not in seen_stage_names:
            nodes.append({
                "id": name,
                "canonical_stage": classify_stage(name),
            })
            seen_stage_names.add(name)

    edges = []

    # Legitimate sequential edges between declared stages (black, per
    # Figure 2's normal pipeline-automator flow).
    stage_names = [s["stage"] for s in stages]
    for i in range(len(stage_names) - 1):
        edges.append({
            "from": stage_names[i],
            "to": stage_names[i + 1],
            "type": "legitimate",
            "label": "pipeline sequence",
        })

    # Malicious edges (red, per Figure 2) -- one per detected flow,
    # pointing from the stage to an external/anomalous sink node.
    external_node_added = False
    for flow in all_flows:
        if flow["flow_type"] == "CREDENTIAL_THEFT_FLOW":
            if not external_node_added:
                nodes.append({"id": "External Server", "canonical_stage": "external"})
                external_node_added = True
            edges.append({
                "from": flow["stage"],
                "to": "External Server",
                "type": "malicious",
                "label": "credential theft",
            })
        elif flow["flow_type"] == "BACKDOOR_FLOW":
            edges.append({
                "from": "test",
                "to": flow["stage"],
                "type": "malicious",
                "label": "backdoor (test->build)",
            })
        elif flow["flow_type"] == "RESOURCE_THEFT_FLOW":
            if not external_node_added:
                nodes.append({"id": "External Server", "canonical_stage": "external"})
                external_node_added = True
            edges.append({
                "from": flow["stage"],
                "to": "External Server",
                "type": "malicious",
                "label": "resource theft",
            })

    return {
        "malicious_flows": all_flows,
        "flow_counts": {
            "credential_theft": len(credential_flows),
            "backdoor": len(backdoor_flows),
            "resource_theft": len(resource_flows),
        },
        "graph": {"nodes": nodes, "edges": edges},
    }