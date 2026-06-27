import os

from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

from agent.controller import AgentController
from tools.file_analyzer import analyze_file

app = Flask(__name__)
agent = AgentController()

app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

ALLOWED_EXTENSIONS = {"txt", "pdf", "csv", "json", "log", "docx", "xml" }

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


@app.route("/")
def home():
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
    app.run(debug=True, port=5001)