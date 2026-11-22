import math
import re
from flask import Flask, Response, render_template_string, request

app = Flask(__name__)

PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "OpenAI API Key": r"sk-[A-Za-z0-9\-_]{20,}",
    "Hardcoded Secret / Password": r"(?i)(password|passwd|secret_key|api_key|token)\s*=\s*['\"][^'\"]{6,}['\"]",
}


def calculate_entropy(data: str) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def sanitize_env_name(name: str, index: int) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    if not cleaned:
        cleaned = "DETECTED_SECRET"
    return f"{cleaned}_{index}"


def analyze_and_fix(content: str, entropy_threshold: float = 4.2) -> dict:
    findings = []
    env_entries = {}
    counter = 1
    fixed_lines = []

    assignment_regex = re.compile(
        r"^(\s*)([A-Za-z0-9_]*(?:password|passwd|secret|api_key|apikey|token)[A-Za-z0-9_]*)\s*=\s*(['\"])([^'\"]{6,})\3(.*)$",
        re.IGNORECASE,
    )
    token_regex = re.compile(r"[A-Za-z0-9_\-+/=]{16,}")

    for line_no, line in enumerate(content.splitlines(), start=1):
        line_flagged = False
        for label, pat in PATTERNS.items():
            for m in re.finditer(pat, line):
                findings.append({
                    "line": line_no,
                    "type": label,
                    "detail": f"Matched pattern: {label}",
                })
                line_flagged = True

        if not line_flagged:
            for tok in token_regex.findall(line):
                score = calculate_entropy(tok)
                if score >= entropy_threshold:
                    findings.append({
                        "line": line_no,
                        "type": "High Entropy String",
                        "detail": f"Entropy score: {round(score, 2)}",
                    })

        assign_match = assignment_regex.match(line)
        if assign_match:
            indent, var_name, _, secret_val, trailing = assign_match.groups()
            env_key = sanitize_env_name(var_name, counter)
            counter += 1
            env_entries[env_key] = secret_val
            fixed_lines.append(f'{indent}{var_name} = os.getenv("{env_key}"){trailing}')
            continue

        def replace_token(match):
            nonlocal counter
            candidate = match.group(0)
            if calculate_entropy(candidate) >= entropy_threshold:
                env_key = sanitize_env_name("SECRET", counter)
                counter += 1
                env_entries[env_key] = candidate
                return f'os.getenv("{env_key}")'
            return candidate

        fixed_lines.append(token_regex.sub(replace_token, line))

    fixed_code = "\n".join(fixed_lines)
    if env_entries and "import os" not in fixed_code:
        fixed_code = "import os\n\n" + fixed_code

    env_text = "\n".join(f"{k}={v}" for k, v in env_entries.items())
    if env_text:
        env_text += "\n"

    return {
        "findings": findings,
        "fixed_code": fixed_code,
        "env_text": env_text,
        "count": len(env_entries),
    }


DEFAULT_SAMPLE = """DB_HOST = "localhost"
OPENAI_API_KEY = "sk-demo1234567890abcdef1234567890"
DB_PASSWORD = "SuperSecretDemoPassword99"
SERVICE_TOKEN = "x9K2mP8vL4nQ7wR3zT6yB1cF5hJ0dG8s"
"""

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Secret Leak Guard — Before & After</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      margin: 0;
      padding: 24px;
    }
    h1 { margin-top: 0; color: #38bdf8; }
    .subtitle { color: #94a3b8; margin-bottom: 20px; }
    textarea {
      width: 100%;
      height: 170px;
      background: #1e293b;
      color: #f8fafc;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 12px;
      font-family: monospace;
      font-size: 14px;
      box-sizing: border-box;
    }
    button.primary {
      margin-top: 12px;
      background: #0284c7;
      color: white;
      border: none;
      padding: 10px 20px;
      border-radius: 6px;
      font-size: 15px;
      cursor: pointer;
    }
    button.primary:hover { background: #0369a1; }
    .btn-download {
      display: inline-block;
      margin-top: 10px;
      background: #10b981;
      color: #06281e;
      font-weight: bold;
      text-decoration: none;
      padding: 8px 14px;
      border-radius: 6px;
      font-size: 13px;
    }
    .btn-download:hover { background: #34d399; }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
      margin-top: 24px;
    }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 16px;
    }
    .card h3 { margin-top: 0; }
    pre {
      background: #0b1120;
      padding: 12px;
      border-radius: 6px;
      overflow-x: auto;
      font-size: 13px;
      line-height: 1.5;
    }
    .alert {
      background: #451a1a;
      border-left: 4px solid #ef4444;
      padding: 8px 12px;
      margin-bottom: 8px;
      border-radius: 4px;
      font-size: 13px;
    }
    .badge {
      display: inline-block;
      background: #065f46;
      color: #a7f3d0;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 13px;
      margin-bottom: 12px;
    }
  </style>
</head>
<body>
  <h1>Secret Leak Guard</h1>
  <p class="subtitle">Detect hardcoded secrets and high-entropy tokens, then auto-fix into environment variables.</p>

  <form method="POST">
    <label><strong>Input Code / Config:</strong></label>
    <textarea name="code">{{ raw_code }}</textarea>
    <button class="primary" type="submit">Scan & Auto-Fix</button>
  </form>

  {% if result is not none %}
    <div style="margin-top: 20px;">
      <span class="badge">Secrets Detected & Replaced: {{ result.count }}</span>
      {% if result.findings %}
        <div>
          {% for item in result.findings %}
            <div class="alert">
              <strong>Line {{ item.line }}</strong> — {{ item.type }} ({{ item.detail }})
            </div>
          {% endfor %}
        </div>
      {% endif %}
    </div>

    <div class="grid">
      <div class="card">
        <h3>After Auto-Fix (Safe Code)</h3>
        <pre>{{ result.fixed_code }}</pre>
        <form method="POST" action="/download/code">
          <input type="hidden" name="code" value="{{ raw_code | e }}" />
          <button class="btn-download" type="submit">Download cleaned_code.py</button>
        </form>
      </div>
      <div class="card">
        <h3>Generated .env File</h3>
        <pre>{{ result.env_text or "# No secrets extracted" }}</pre>
        <form method="POST" action="/download/env">
          <input type="hidden" name="code" value="{{ raw_code | e }}" />
          <button class="btn-download" type="submit">Download .env</button>
        </form>
      </div>
    </div>
  {% endif %}
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    raw_code = DEFAULT_SAMPLE
    result = None
    if request.method == "POST":
        raw_code = request.form.get("code", "")
        result = analyze_and_fix(raw_code)
    return render_template_string(HTML_TEMPLATE, raw_code=raw_code, result=result)


@app.route("/download/code", methods=["POST"])
def download_code():
    raw_code = request.form.get("code", "")
    result = analyze_and_fix(raw_code)
    return Response(
        result["fixed_code"],
        mimetype="text/x-python",
        headers={"Content-Disposition": "attachment; filename=cleaned_code.py"},
    )


@app.route("/download/env", methods=["POST"])
def download_env():
    raw_code = request.form.get("code", "")
    result = analyze_and_fix(raw_code)
    return Response(
        result["env_text"] or "# No secrets extracted\n",
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=.env"},
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)