# web_ui_bootstrap1.py
"""
Flask UI with Bootstrap for OWASP Juice Shop Vulnerability Scanner
Run with: python web_ui_bootstrap1.py
Then open: http://127.0.0.1:5000
"""

import os
import shlex
import subprocess
import threading
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string, send_file
import datetime
import glob
import time

APP_DIR = Path(__file__).parent.resolve()
DEFAULT_TARGET = "http://localhost:3000"
SCANNER_SCRIPT = APP_DIR / "juice_scan1.py"  # or juice_scan.py
LOG_FILE = APP_DIR / "juice_scan_stdout.log"
# Note: We removed JSON support per your request. Reports will be TXT files named scan_report_YYYY-MM-DD.txt

app = Flask(__name__)

proc_lock = threading.Lock()
current_proc = None
current_target = None
last_error = None
last_report_path = None

# --- Bootstrap HTML template ---
INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Juice Shop Vulnerability Scanner</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
   <style>
    body {
      background-image: url('/static/bg.jpg');
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
      padding-top: 30px;
    }
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
      <form id="scanForm" class="row g-3 mb-4" onsubmit="return false;">
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
        <a id="reportLink" href="#" class="btn btn-success btn-lg" style="display:none;">Download TXT Report</a>
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
  document.getElementById('reportLink').style.display = 'none';
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
    document.getElementById('reportLink').href = '/report';
    document.getElementById('reportLink').style.display = 'inline-block';
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

def create_dated_report(target):
    """
    Read the LOG_FILE and copy its full contents into a dated TXT report.
    Filename: scan_report_YYYY-MM-DD.txt
    Returns the Path to the created report.
    """
    try:
        today = datetime.date.today().isoformat()  # YYYY-MM-DD
        report_name = f"scan_report_{today}.txt"
        report_path = APP_DIR / report_name
        # Read full log (if missing, create with a short message)
        content = ""
        if LOG_FILE.exists():
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        else:
            content = f"No scanner log found for target {target}.\n"
        # Prepend a header with timestamp and target
        header = f"Scan Report - {datetime.datetime.now().isoformat()}\nTarget: {target}\n\n"
        with open(report_path, "w", encoding="utf-8") as out:
            out.write(header)
            out.write(content)
        return report_path
    except Exception as e:
        # shouldn't raise to the caller thread uncaught
        return None

def run_scanner(target):
    global current_proc, last_error, last_report_path
    try:
        # remove old log to avoid mixing previous output
        if LOG_FILE.exists():
            try:
                LOG_FILE.unlink()
            except Exception:
                pass

        args = [str(os.sys.executable), str(SCANNER_SCRIPT), target]
        with open(LOG_FILE, "wb") as out:
            p = subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT)
        with proc_lock:
            current_proc = p
        # Wait for scanner to finish
        p.wait()
        with proc_lock:
            current_proc = None

        # After scanner finishes, create dated TXT report from the log
        rpt = create_dated_report(target)
        if rpt:
            last_report_path = str(rpt)
        else:
            last_report_path = None

    except Exception as e:
        last_error = str(e)
        current_proc = None
        last_report_path = None

@app.route("/")
def index():
    return render_template_string(INDEX_HTML, default_target=DEFAULT_TARGET)

@app.route("/start", methods=["POST"])
def start():
    global current_target, last_error, last_report_path
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
        last_report_path = None
    return jsonify({"status":"running", "target":target})

@app.route("/status")
def status():
    with proc_lock:
        proc = current_proc
    if proc is None:
        # not running
        if last_report_path and Path(last_report_path).exists():
            return jsonify({"status":"finished", "target": current_target, "log": read_log_tail()})
        elif last_error:
            return jsonify({"status":"error", "error": last_error, "log": read_log_tail()})
        else:
            # idle, maybe before any scan
            # try to detect any existing today's report to allow manual download
            today_glob = str(APP_DIR / "scan_report_*.txt")
            matches = glob.glob(today_glob)
            if matches:
                return jsonify({"status":"finished", "target": current_target, "log": read_log_tail()})
            return jsonify({"status":"idle", "log": read_log_tail()})
    else:
        return jsonify({"status":"running", "target": current_target, "log": read_log_tail()})

@app.route("/report")
def report():
    """
    Return the most recent scan_report_YYYY-MM-DD.txt file as an attachment.
    """
    # Prefer last_report_path if available
    global last_report_path
    try:
        if last_report_path and Path(last_report_path).exists():
            p = Path(last_report_path)
            return send_file(str(p), as_attachment=True, download_name=p.name)
        # fallback: find the newest scan_report_*.txt in APP_DIR
        pattern = APP_DIR / "scan_report_*.txt"
        files = list(pattern.parent.glob(pattern.name))
        if not files:
            return "Report not found", 404
        # pick newest by modified time
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        latest = files[0]
        return send_file(str(latest), as_attachment=True, download_name=latest.name)
    except Exception as e:
        return f"Error serving report: {e}", 500

if __name__ == "__main__":
    if not SCANNER_SCRIPT.exists():
        print(f"Scanner script not found: {SCANNER_SCRIPT}")
        exit(1)
    print("🚀 Flask UI running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
