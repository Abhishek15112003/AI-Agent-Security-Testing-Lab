import os
from flask import Flask, render_template, send_file, request
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

from agent.controller import AgentController
from tools.file_analyzer import analyze_file

app = Flask(__name__)
agent = AgentController()

app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

ALLOWED_EXTENSIONS = {"txt", "pdf", "csv", "json", "log", "docx"}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def allowed_file(filename: str) -> bool:
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def render_error(message: str, status: int = 400):
    return render_template("agent.html", error=message), status


@app.errorhandler(RequestEntityTooLarge)
def handle_oversize_upload(_e):
    limit_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    return render_error(f"File exceeds the {limit_mb} MB size limit.")


def get_security_events():
    events = []
    try:
        with open("logs/security.log", "r", encoding="utf-8") as logfile:
            lines = logfile.readlines()
            for line in reversed(lines):
                parts = line.strip().split("|")
                if len(parts) == 3:
                    events.append({
                        "timestamp": parts[0].strip(),
                        "severity": parts[1].strip(),
                        "event": parts[2].strip()
                    })
    except Exception:
        pass
    return events


def get_event_metrics():
    high = 0
    medium = 0
    low = 0
    try:
        with open("logs/security.log", "r", encoding="utf-8") as logfile:
            for line in logfile:
                parts = line.strip().split("|")
                if len(parts) != 3:
                    continue
                severity = parts[1].strip()
                if severity == "HIGH":
                    high += 1
                elif severity == "MEDIUM":
                    medium += 1
                elif severity == "LOW":
                    low += 1
    except Exception:
        pass
    return {
        "high": high,
        "medium": medium,
        "low": low,
        "total": high + medium + low
    }


def calculate_security_score():
    metrics = get_event_metrics()
    score = 100
    score -= metrics["high"] * 5
    score -= metrics["medium"] * 2
    score -= metrics["low"] * 1
    return max(score, 0)


def calculate_risk_level():
    score = calculate_security_score()
    if score >= 80:
        return "LOW"
    elif score >= 50:
        return "MEDIUM"
    return "HIGH"


@app.route("/")
def dashboard():
    score = calculate_security_score()
    risk = calculate_risk_level()
    metrics = get_event_metrics()
    
    # Read security events
    security_events = get_security_events()
    
    # Map to timeline
    attack_timeline = []
    for event in security_events:
        attack_timeline.append({
            "time": event["timestamp"],
            "event": event["event"]
        })
        
    # Categorize attacks for stats
    attack_stats = {
        "Prompt Injection": 0,
        "Knowledge Base Poisoning": 0,
        "Path Traversal": 0,
        "Inter-Agent Spoofing": 0
    }
    for event in security_events:
        ev_lower = event["event"].lower()
        if "prompt" in ev_lower or "injection" in ev_lower:
            attack_stats["Prompt Injection"] += 1
        elif "knowledge" in ev_lower or "kb" in ev_lower or "poison" in ev_lower:
            attack_stats["Knowledge Base Poisoning"] += 1
        elif "traversal" in ev_lower or "path" in ev_lower:
            attack_stats["Path Traversal"] += 1
        elif "spoofing" in ev_lower or "inter-agent" in ev_lower:
            attack_stats["Inter-Agent Spoofing"] += 1

    # Load findings
    findings = []
    failed_categories = set()
    findings_file = "reports/findings.txt"
    if os.path.exists(findings_file):
        try:
            with open(findings_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        findings.append(line)
                        parts = line.split("|")
                        if len(parts) >= 1:
                            test_id = parts[0].strip()
                            category = test_id.split("-")[-2] if "CHAIN" in test_id else test_id.split("-")[0]
                            failed_categories.add(category)
        except Exception:
            pass

    # Security Summary dict
    top_attack = "None"
    top_attack_count = 0
    for att, count in attack_stats.items():
        if count > top_attack_count:
            top_attack = att
            top_attack_count = count
            
    security_summary = {
        "total_events": metrics["total"],
        "high_events": metrics["high"],
        "risk": risk,
        "top_attack": top_attack,
        "top_attack_count": top_attack_count
    }

    # OWASP Coverage Status
    owasp_coverage = [
        {"id": "ASI01", "name": "Agent Goal Hijack", "status": "ASI01" not in failed_categories},
        {"id": "ASI02", "name": "Tool Misuse", "status": "ASI02" not in failed_categories},
        {"id": "ASI03", "name": "Privilege Abuse", "status": "ASI03" not in failed_categories},
        {"id": "ASI06", "name": "Memory Poisoning", "status": "ASI06" not in failed_categories},
        {"id": "ASI07", "name": "Inter-Agent Spoofing", "status": "ASI07" not in failed_categories},
    ]

    return render_template(
        "dashboard.html",
        score=score,
        risk=risk,
        metrics=metrics,
        security_summary=security_summary,
        owasp_coverage=owasp_coverage,
        findings=findings,
        attack_stats=attack_stats,
        attack_timeline=attack_timeline,
        security_events=security_events
    )


@app.route("/download_report")
def download_report():
    assessment_path = "reports/assessment_report.txt"
    hardening_path = "reports/hardening_report.txt"
    
    if os.path.exists(assessment_path):
        return send_file(assessment_path, as_attachment=True)
    elif os.path.exists(hardening_path):
        return send_file(hardening_path, as_attachment=True)
    else:
        os.makedirs("reports", exist_ok=True)
        with open(assessment_path, "w", encoding="utf-8") as f:
            f.write("AI Agent Security Assessment\n\nNo report generated yet. Run test suite first.")
        return send_file(assessment_path, as_attachment=True)


@app.route("/agent")
def agent_home():
    return render_template("agent.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    user_input = request.form.get("user_input", "").strip()

    if not user_input:
        return render_error("Please provide input.")

    try:
        result = agent.process_request(user_input)
    except Exception as e:
        app.logger.exception("Agent error")
        return render_error("Something went wrong processing your request.", 500)

    return render_template("agent.html", result=result, user_input=user_input)


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return render_error("No file selected.")

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return render_error("No file selected.")

    if not allowed_file(uploaded_file.filename):
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        return render_error(f"File type not allowed. Accepted types: {allowed}")

    filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    uploaded_file.save(filepath)

    try:
        result = analyze_file(filepath)
    except Exception as e:
        app.logger.exception("Analysis error for %s", filename)
        return render_error("File uploaded but analysis failed.", 500)

    return render_template("agent.html", result=result, uploaded_file=filename)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
