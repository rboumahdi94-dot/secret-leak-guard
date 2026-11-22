# Secret Leak Guard

A lightweight security tool built with **Python** and **Flask** that scans code or configuration snippets for hardcoded secrets and high-entropy tokens, rewrites exposed values into environment variables (`os.getenv(...)`), and generates a `.env` file with one click.

---

## Features

* **Pattern Matching (Regex):** Detects common credential formats (such as AWS access keys, GitHub tokens, and OpenAI API keys) as well as hardcoded password/secret assignments.
* **Shannon Entropy Analysis:** Flags long, high-randomness strings that may indicate tokens or secrets even when they do not match a known prefix.
* **Line-by-Line Findings:** Displays line numbers, leak categories, and detection reasons.
* **One-Click Auto-Fix & Export:** Replaces hardcoded secrets with `os.getenv(...)` calls in the cleaned code, generates `.env` entries, and lets you download both `cleaned_code.py` and `.env`.

---

## Project Structure

```text
Secret Leak Guard/
├── app.py          # Flask web app, detection engine, and auto-fix/download routes
└── README.md       # Project documentation