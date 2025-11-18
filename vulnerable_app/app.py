from flask import Flask, request, render_template, send_from_directory, redirect, url_for
import sqlite3
import hashlib
import os
import glob
import sys

# Base paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)

# Import analyzer modules to enable in-app runs
import sys
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)
from analyzer.dast import scan_sql_injection
from analyzer.sast import analyze_python_file
from analyzer.dump_audit import identify_hashes_from_dump
from analyzer.correlate import correlate
from analyzer.report import to_json, to_markdown, to_html

app = Flask(__name__)

# Paths
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
SEED_DIR = os.path.join(BASE_DIR, "seed_data")
SOURCE_DIR_DEFAULT = os.path.join(BASE_DIR, "vulnerable_app")
TARGET_DEFAULT = "http://127.0.0.1:5000"


def get_db():
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, user TEXT, pass TEXT)")
    # seed with weak hashes
    c.execute("INSERT INTO users(user, pass) VALUES (?, ?)", ("alice", hashlib.md5(b"password").hexdigest()))
    c.execute("INSERT INTO users(user, pass) VALUES (?, ?)", ("bob", hashlib.sha1(b"hunter2").hexdigest()))
    conn.commit()
    return conn


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    # List available dumps
    dumps = []
    if os.path.isdir(SEED_DIR):
        for f in glob.glob(os.path.join(SEED_DIR, "*")):
            dumps.append(os.path.relpath(f, BASE_DIR))
    return render_template(
        "dashboard.html",
        target_default=TARGET_DEFAULT,
        source_default=os.path.relpath(SOURCE_DIR_DEFAULT, BASE_DIR),
        dumps=dumps,
        out_default=os.path.relpath(REPORTS_DIR, BASE_DIR),
    )


@app.route("/run_analyzer", methods=["POST"])
def run_analyzer():
    target = request.form.get("target", TARGET_DEFAULT)
    source_dir = request.form.get("source_dir", SOURCE_DIR_DEFAULT)
    dump = request.form.get("dump", os.path.join(SEED_DIR, "users_dump.sql"))
    out_dir = request.form.get("out_dir", REPORTS_DIR)
    gen_html = request.form.get("html") == "on"

    # Normalize relative paths to absolute from BASE_DIR
    if not os.path.isabs(source_dir):
        source_dir = os.path.join(BASE_DIR, source_dir)
    if not os.path.isabs(dump):
        dump = os.path.join(BASE_DIR, dump)
    if not os.path.isabs(out_dir):
        out_dir = os.path.join(BASE_DIR, out_dir)

    # Build candidate URLs
    urls = [
        f"{target}/search?q=test",
        f"{target}/login?user=alice&pass=pass",
        f"{target}/item?id=1",
    ]

    # DAST
    dast_findings = scan_sql_injection(urls)

    # SAST
    py_files = glob.glob(os.path.join(source_dir, "**", "*.py"), recursive=True)
    sast_findings = []
    for f in py_files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                src = fh.read()
            sast_findings.extend(analyze_python_file(f, src))
        except Exception:
            continue

    # Dump audit
    dump_findings = []
    try:
        with open(dump, "r", encoding="utf-8") as fh:
            dump_text = fh.read()
        dump_findings = identify_hashes_from_dump(dump_text)
    except Exception:
        pass

    # Correlate
    risk = correlate(dast_findings, sast_findings, dump_findings)

    # Write reports
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as fh:
        fh.write(to_json(risk))
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(to_markdown(risk))
    if gen_html:
        with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as fh:
            fh.write(to_html(risk))

    return redirect(url_for("view_report"))


@app.route("/reports/<path:filename>")
def serve_report_file(filename: str):
    # Serve files from the reports directory
    return send_from_directory(REPORTS_DIR, filename)


@app.route("/view_report")
def view_report():
    # Redirect to the HTML report if available; otherwise show JSON
    html_path = os.path.join(REPORTS_DIR, "report.html")
    if os.path.exists(html_path):
        return send_from_directory(REPORTS_DIR, "report.html")
    return send_from_directory(REPORTS_DIR, "report.json")


@app.route("/health")
def health():
    return {"status": "healthy"}


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    c = conn.cursor()
    # intentionally vulnerable: inline f-string at execute() call
    rows = c.execute(f"SELECT user FROM users WHERE user LIKE '%{q}%' ").fetchall()
    return {"results": [r[0] for r in rows]}


@app.route("/item")
def item():
    item_id_raw = request.args.get("id", "1")
    conn = get_db()
    c = conn.cursor()
    # intentionally vulnerable: inline string concatenation at execute() call
    rows = c.execute("SELECT user FROM users WHERE id = " + item_id_raw).fetchall()
    return {"results": [r[0] for r in rows]}


@app.route("/login")
def login():
    user = request.args.get("user", "")
    password = request.args.get("pass", "")
    # intentionally vulnerable: store plaintext password variable
    stored_password = password
    return {"status": "ok", "user": user}


@app.errorhandler(404)
def handle_404(e):
    return {
        "error": "Not Found",
        "hint": "Use one of the available routes",
        "endpoints": [
            "/",
            "/health",
            "/search?q=test",
            "/item?id=1",
            "/login?user=alice&pass=password",
        ],
    }, 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)