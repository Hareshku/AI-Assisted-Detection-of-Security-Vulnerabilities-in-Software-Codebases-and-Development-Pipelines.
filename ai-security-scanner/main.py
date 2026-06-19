from scanner.flow_tracker import analyze_flows
from scanner.analyzer import analyze_file
import sys
import os
from colorama import init, Fore, Style

from scanner.parser import parse_file
from scanner.extractor import extract_features
from scanner.risk_engine import calculate_risk_score, get_risk_emoji
from scanner.ml_model import predict_vulnerability

# Initialize colorama for Windows colored output
init(autoreset=True)


def print_banner():
    print(Fore.CYAN + """
╔══════════════════════════════════════════════╗
║       🛡️  AI SECURITY SCANNER v1.0           ║
║   Detect vulnerabilities in code & pipelines ║
╚══════════════════════════════════════════════╝
    """ + Style.RESET_ALL)


def scan_file(filepath):
    """Full pipeline: Parse → Extract → Flow Analysis → Score → ML Predict → Rule Analysis"""

    print(Fore.YELLOW + f"\n🔍 Scanning: {filepath}" + Style.RESET_ALL)

    # Step 1: Parse
    parse_result = parse_file(filepath)
    if parse_result["status"] != "success":
        print(Fore.RED + f"❌ Error: {parse_result['error']}" + Style.RESET_ALL)
        return

    # Step 2: Extract features
    features = extract_features(parse_result)

    # Step 3: Flow analysis (must run BEFORE scoring, since score uses it)
    flow_result = analyze_flows(parse_result) if features.get("file_type") == "pipeline" else None

    # Step 4: Risk score (now includes flow detections)
    risk = calculate_risk_score(features, flow_result)

    # Step 5: ML prediction
    ml = predict_vulnerability(features)

    # Step 6: Rule-based analysis
    analysis = analyze_file(parse_result)

    # ── Display Results ──
    emoji = get_risk_emoji(risk["risk_level"])
    level = risk["risk_level"]

    if level == "HIGH":
        color = Fore.RED
    elif level == "MEDIUM":
        color = Fore.YELLOW
    else:
        color = Fore.GREEN

    print("─" * 50)
    print(f"  File       : {os.path.basename(filepath)}")
    print(f"  Type       : {features.get('file_type', 'unknown').upper()}")
    print(color + f"  Risk Level : {emoji}  {level}" + Style.RESET_ALL)
    print(color + f"  Risk Score : {risk['score']} / 100" + Style.RESET_ALL)
    print(f"  ML Result  : {ml.get('prediction')} "
          f"({ml.get('probability', 0) * 100:.1f}% confidence)")

    print(f"\n  📋 Findings:")
    if risk["reasons"]:
        for reason in risk["reasons"]:
            print(Fore.YELLOW + f"     ⚠️  {reason}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "     ✅ No threats detected" + Style.RESET_ALL)

    print(f"\n  🛡️  Rule Violations: {analysis['total_violations']} "
          f"(🔴 {analysis['high']} HIGH  🟡 {analysis['medium']} MEDIUM  🟢 {analysis['low']} LOW)")

    if analysis["violations"]:
        for v in analysis["violations"]:
            v_color = Fore.RED if v["severity"] == "HIGH" else \
                       Fore.YELLOW if v["severity"] == "MEDIUM" else Fore.GREEN
            print(v_color + f"     [{v['rule_id']}] {v['name']}" + Style.RESET_ALL)

    if flow_result:
        print(f"\n  🔀 Malicious Flows (paper-based): {len(flow_result['malicious_flows'])}")
        for flow in flow_result["malicious_flows"]:
            print(Fore.RED + f"     [{flow['flow_type']}] {flow['stage']} stage" + Style.RESET_ALL)
            print(f"        {flow['evidence']}")

    print("─" * 50)

def scan_folder(folder_path):
    """Scans all .py, .yml, .yaml files in a folder"""

    supported = ('.py', '.yml', '.yaml')
    found = []

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(supported):
                found.append(os.path.join(root, file))

    if not found:
        print(Fore.RED + "❌ No supported files found in folder." + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n📁 Found {len(found)} file(s) to scan..." + Style.RESET_ALL)
    for filepath in found:
        scan_file(filepath)


def main():
    print_banner()

    # If no arguments given, scan the samples folder by default
    if len(sys.argv) < 2:
        print(Fore.CYAN + "Usage:" + Style.RESET_ALL)
        print("  Scan a file   : python main.py data/samples/bad_code.py")
        print("  Scan a folder : python main.py data/samples/")
        print("\n" + Fore.YELLOW +
              "No path given — scanning data/samples/ by default..." +
              Style.RESET_ALL)
        scan_folder("data/samples/")
        return

    target = sys.argv[1]

    if os.path.isfile(target):
        scan_file(target)

    elif os.path.isdir(target):
        scan_folder(target)

    else:
        print(Fore.RED + f"❌ Path not found: {target}" + Style.RESET_ALL)


if __name__ == "__main__":
    main()