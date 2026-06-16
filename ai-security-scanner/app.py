from scanner.flow_tracker import analyze_flows
from scanner.analyzer import analyze_file
import os
import tempfile
from flask import Flask, render_template, request, jsonify
from scanner.parser import parse_file
from scanner.extractor import extract_features
from scanner.risk_engine import calculate_risk_score
from scanner.ml_model import predict_vulnerability

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'.py', '.yml', '.yaml'}

def allowed_file(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    if 'files' not in request.files:
        return jsonify({"error": "No files uploaded"}), 400

    files = request.files.getlist('files')
    results = []

    for file in files:
        if not file or not allowed_file(file.filename):
            continue

        ext = os.path.splitext(file.filename)[1].lower()
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=ext, mode='wb'
        ) as tmp:
            file.save(tmp)
            tmp_path = tmp.name

        try:
            parse_result = parse_file(tmp_path)

            if parse_result["status"] != "success":
                results.append({
                    "filename": file.filename,
                    "error":    parse_result.get("error", "Parse error")
                })
                continue

            features   = extract_features(parse_result)
            risk       = calculate_risk_score(features)
            ml_result  = predict_vulnerability(features)
            analysis   = analyze_file(parse_result)
            flow_result = analyze_flows(parse_result) if features.get("file_type") == "pipeline" else None

            # results.append({
            #     "filename":        file.filename,
            #     "file_type":       features.get("file_type"),
            #     "risk_score":      risk["score"],
            #     "risk_level":      risk["risk_level"],
            #     "reasons":         risk["reasons"],
            #     "ml_prediction":   ml_result.get("prediction"),
            #     "ml_probability":  ml_result.get("probability", 0),
            #     "violations":      analysis.get("violations", []),
            #     "violation_counts": {
            #         "high":   analysis.get("high", 0),
            #         "medium": analysis.get("medium", 0),
            #         "low":    analysis.get("low", 0),
            #     },
            # })
            
            results.append({
                "filename":        file.filename,
                "file_type":       features.get("file_type"),
                "risk_score":      risk["score"],
                "risk_level":      risk["risk_level"],
                "reasons":         risk["reasons"],
                "ml_prediction":   ml_result.get("prediction"),
                "ml_probability":  ml_result.get("probability", 0),
                "violations":      analysis.get("violations", []),
                "violation_counts": {
                    "high":   analysis.get("high", 0),
                    "medium": analysis.get("medium", 0),
                    "low":    analysis.get("low", 0),
                },
                "flow_analysis": flow_result,
            })

        finally:
            os.unlink(tmp_path)

    return jsonify({"results": results})

if __name__ == '__main__':
    app.run(debug=True)