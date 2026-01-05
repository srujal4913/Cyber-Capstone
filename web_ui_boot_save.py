# web_ui.py
"""
Flask UI with Bootstrap + auto text report generation.
Run: python web_ui.py
Open: http://127.0.0.1:5000
"""

import os
import subprocess
import threading
import json
import re
import time
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string, send_file

APP_DIR = Path(__file__).parent.resolve()
DEFAULT_TARGET = "http://localhost:3000"
SCANNER_SCRIPT = APP_DIR / "juice_scan.py"  # change to juice_scan.py if you prefer
REPORT_FILE = APP_DIR / "juice_scan_report.json"
LOG_FILE = APP_DIR / "juice_scan_stdout.log"
REPORTS_DIR = APP_DIR / "reports"

# ensure reports dir exists
REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)

proc_lock = threading.Lock()
current_proc = None
current_target = None
last_error = None

# Bootstrap HTML template (adds link for TXT report)
INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Juice Shop Vulnerability Scanner</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background-color: #f5f7fa; padding-top: 30px; }
    .log-box { background-color: #111; color: #0f0; font-family: monospace; white-space: pre-wrap;
               padding: 10px; border-radius: 10px; height: 400px; overflow-y: auto; }
    .card { box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
    footer { margin-top: 40px; color: #666; text-align: center; font-size: 0.9em; }
  </style>
</head>
<body>
<div class="container">
  <div class="card mx-auto" style="max-width:900px;">
    <div class="card-body">
      <h3 class="card-title text-center mb-4">🧪 Juice Shop Vulnerability Scanner</h3>
      <form id="scanForm" class="row g-3 mb-4">
        <div class="col-md-9">
          <input id="target" name="target" type="text" class="form-control form-control-lg"
                 value="{{ default_target }}" placeholder="Enter target URL (e.g. http://localhost:3000)">
        </div>
        <div class="col-md-3 d-grid">
          <button type="button" class="btn btn-primary btn-lg" onclick="startScan()">Start Scan</button>
        </div>
      </form>

      <div id="statusBox" class="alert alert-info">Status: <span id="status">idle</span></div>

      <div class="mb-3">
        <label class="form-label fw-bold">Scanner Output:</label>
        <div id="log" class="log-box"></div>
      </div>

      <div class="text-center">
        <a id="jsonReportLink" href="#" class="btn btn-success me-2" style="display:none;">Download JSON Report</a>
        <a id="txtReportLink" href="#" class="btn btn-secondary" style="display:none;">Download TXT Report</a>
      </div>
    </div>
  </div>
  <footer class="mt-4">
    <p>© 2025 OWASP Juice Shop Scanner | Built with Flask + Bootstrap 5</p>
  </footer>
</div>

<script>
let pollInterval = null;

async function startScan() {
  document.getElementById('jsonReportLink').style.display = 'none';
  document.getElementById('txtReportLink').style.display = 'none';
  document.getElementById('log').innerText = '';
  document.getElementById('status').innerText = 'starting...';

  const target = document.getElementById('target').value;
  const r = await fetch('/start', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ target })
  });
  const j = await r.json();
  document.getElementById('status').innerText = j.status;
  updateStatusColor(j.status);
  if (!pollInterval) pollInterval = setInterval(pollStatus, 1500);
}

async function pollStatus() {
  const r = await fetch('/status');
  const j = await r.json();
  document.getElementById('status').innerText = j.status + (j.target ? ' ('+j.target+')' : '');
  updateStatusColor(j.status);
  document.getElementById('log').innerText = j.log || '';
  const logBox = document.getElementById('log');
  logBox.scrollTop = logBox.scrollHeight;
  if (j.status === 'finished') {
    if (j.json_report_url) {
      document.getElementById('jsonReportLink').href = j.json_report_url;
      document.getElementById('jsonReportLink').style.display = 'inline-block';
    }
    if (j.txt_report_url) {
      document.getElementById('txtReportLink').href = j.txt_report_url;
      document.getElementById('txtReportLink').style.display = 'inline-block';
    }
    clearInterval(pollInterval); pollInterval = null;
  } else if (j.status === 'error') {
    clearInterval(pollInterval); pollInterval = null;
    alert('Scanner error: ' + (j.error || 'unknown'));
  }
}

function updateStatusColor(status) {
  const box = document.getElementById('statusBox');
  box.className = 'alert';
  if (status.includes('running')) box.classList.add('alert-warning');
  else if (status.includes('finished')) box.classList.add('alert-success');
  else if (status.includes('error')) box.classList.add('alert-danger');
  else box.classList.add('alert-info');
}
</script>
</body>
</html>
"""

def read_log_tail(max_bytes=20000):
    try:
        if not LOG_FILE.exists():
            return ""
        with open(LOG_FILE, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            return f.read().decode(errors="ignore")
    except Exception as e:
        return f"[Error reading log: {e}]"

def safe_filename(s: str) -> str:
    # make a filesystem-safe name from a URL or string
    s = s.lower()
    s = re.sub(r"https?://", "", s)
    s = re.sub(r"[^a-z0-9._-]+", "_", s)
    s = s.strip("_")
    return s[:200]

def generate_text_report(json_path: Path, target: str) -> Path:
    """
    Read the JSON report and write a human-readable text file in REPORTS_DIR.
    Returns the Path to the created text report.
    """
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        raise RuntimeError(f"Could not read JSON report: {e}")

    now = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_target = safe_filename(target)
    txt_name = f"{safe_target}_{now}.txt"
    txt_path = REPORTS_DIR / txt_name

    lines = []
    lines.append(f"Juice Shop Scan Report")
    lines.append(f"Target: {target}")
    lines.append(f"Generated: {datetime.utcnow().isoformat()} UTC")
    lines.append("")
    # discovered urls
    discovered = data.get("discovered_urls", [])
    lines.append(f"Discovered URLs: {len(discovered)}")
    for u in discovered[:30]:
        url = u.get("url") if isinstance(u, dict) else str(u)
        status = u.get("status", "")
        lines.append(f" - {url}   [{status}]")
    if len(discovered) > 30:
        lines.append(f"   ... ({len(discovered)-30} more)")
    lines.append("")

    # XSS
    xss = data.get("xss", [])
    lines.append(f"XSS findings: {len(xss)}")
    for i, item in enumerate(xss):
        lines.append(f" {i+1}. URL: {item.get('url')} Param: {item.get('param')} Payload: {item.get('payload')}")
    lines.append("")

    # SQLi
    sqli = data.get("sqli", [])
    lines.append(f"SQLi findings: {len(sqli)}")
    for i, item in enumerate(sqli):
        lines.append(f" {i+1}. URL: {item.get('url')} Payload: {item.get('payload')} Status: {item.get('status')}")
        if item.get("sql_hint"):
            lines.append(f"    Hint: {item.get('sql_hint')}")
    lines.append("")

    # IDOR
    idor = data.get("idor", [])
    lines.append(f"IDOR findings: {len(idor)}")
    for i, item in enumerate(idor):
        lines.append(f" {i+1}. Endpoint: {item.get('endpoint')} Tested ID: {item.get('tested_id')} Status: {item.get('status')}")
    lines.append("")

    # sensitive files
    sensitive = data.get("sensitive", [])
    lines.append(f"Exposed files/paths: {len(sensitive)}")
    for i, item in enumerate(sensitive):
        lines.append(f" {i+1}. Path: {item.get('path')} Status: {item.get('status')}")
        snippet = item.get("snippet", "")
        if snippet:
            lines.append(f"    Snippet: {snippet[:200].replace('\\n',' ')}")
    lines.append("")

    # errors
    errors = data.get("errors", [])
    lines.append(f"Scanner errors: {len(errors)}")
    for e in errors:
        lines.append(f" - {e}")

    # write file
    try:
        with open(txt_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
    except Exception as e:
        raise RuntimeError(f"Could not write text report: {e}")

    return txt_path

def run_scanner(target):
    global current_proc, last_error
    try:
        if LOG_FILE.exists():
            LOG_FILE.unlink()
        args = [str(os.sys.executable), str(SCANNER_SCRIPT), target]
        with open(LOG_FILE, "wb") as out:
            p = subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT)
        with proc_lock:
            current_proc = p
        p.wait()
        with proc_lock:
            current_proc = None
    except Exception as e:
        last_error = str(e)
        current_proc = None

@app.route("/")
def index():
    return render_template_string(INDEX_HTML, default_target=DEFAULT_TARGET)

@app.route("/start", methods=["POST"])
def start():
    global current_target, last_error
    data = request.get_json() or {}
    target = data.get("target") or DEFAULT_TARGET
    with proc_lock:
        if current_proc is not None and current_proc.poll() is None:
            return jsonify({"status":"running", "message":"Scan already running"})
        import threading
        t = threading.Thread(target=run_scanner, args=(target,), daemon=True)
        t.start()
        current_target = target
        last_error = None
    return jsonify({"status":"running", "target":target})

@app.route("/status")
def status():
    global last_error
    with proc_lock:
        proc = current_proc
    # Read current log
    log_tail = read_log_tail()
    if proc is None:
        # If scan finished and JSON report exists -> generate TXT report if not present
        if REPORT_FILE.exists():
            txt_path = None
            # try to find an already generated TXT for the most recent run for this target
            try:
                # check reports dir for files matching target prefix
                safe_target = safe_filename(current_target or "")
                candidates = sorted(REPORTS_DIR.glob(f"{safe_target}_*.txt"), key=os.path.getmtime, reverse=True)
                if candidates:
                    txt_path = candidates[0]
            except Exception:
                txt_path = None

            # if no candidate, try generating one from the JSON report
            if txt_path is None:
                try:
                    txt_path = generate_text_report(REPORT_FILE, current_target or DEFAULT_TARGET)
                except Exception as e:
                    # generation failed, still return finished but include error in log
                    log_tail += f"\n[Report generation error] {e}"
                    return jsonify({"status":"finished", "target": current_target, "log": log_tail, "json_report_url": "/report"})

            # Provide URLs for both JSON and TXT
            json_url = "/report"
            txt_url = f"/reports/{txt_path.name}"
            return jsonify({"status":"finished", "target": current_target, "log": log_tail, "json_report_url": json_url, "txt_report_url": txt_url})
        elif last_error:
            return jsonify({"status":"error", "error": last_error, "log": log_tail})
        else:
            return jsonify({"status":"idle", "log": log_tail})
    else:
        running = (proc.poll() is None)
        return jsonify({"status":"running" if running else "idle", "target": current_target, "log": log_tail, "pid": proc.pid if proc else None})

@app.route("/report")
def report():
    if not REPORT_FILE.exists():
        return "Report not found", 404
    return send_file(str(REPORT_FILE), as_attachment=True, download_name=REPORT_FILE.name)

@app.route("/reports/<path:filename>")
def reports(filename):
    # Serve generated text reports (from REPORTS_DIR)
    safe_path = REPORTS_DIR / Path(filename).name
    if not safe_path.exists():
        return "File not found", 404
    return send_file(str(safe_path), as_attachment=True, download_name=safe_path.name)

if __name__ == "__main__":
    if not SCANNER_SCRIPT.exists():
        print(f"Scanner script not found: {SCANNER_SCRIPT}")
        exit(1)
    print("🚀 Flask UI running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
