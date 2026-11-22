import math
import re


def calculate_entropy(data: str) -> float:
    """(Shannon Entropy)"""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "OpenAI API Key": r"sk-[A-Za-z0-9\-_]{20,}",
    "Hardcoded Password / Secret": r"(?i)(password|passwd|secret_key|api_key|token)\s*=\s*['\"][^'\"]{6,}['\"]",
}


def scan_text(content: str, entropy_threshold: float = 4.2) -> list[dict]:
    
    findings = []
    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):
        matched_spans = []

       
        for label, pattern in PATTERNS.items():
            for match in re.finditer(pattern, line):
                findings.append({
                    "line": line_number,
                    "type": label,
                    "snippet": match.group(0),
                    "reason": f"Matched pattern: {label}",
                })
                matched_spans.append((match.start(), match.end()))

        
        tokens = re.findall(r"[A-Za-z0-9_\-+/=]{16,}", line)
        for token in tokens:
            token_start = line.find(token)
            already_reported = any(
                start <= token_start < end for start, end in matched_spans
            )
            if not already_reported:
                score = calculate_entropy(token)
                if score >= entropy_threshold:
                    findings.append({
                        "line": line_number,
                        "type": "High Entropy String",
                        "snippet": token,
                        "reason": f"Entropy score {round(score, 2)} >= {entropy_threshold}",
                    })

    return findings


def scan_file(file_path: str) -> list[dict]:
    """قراءة ملف وفحص محتواه."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    return scan_text(content)


if __name__ == "__main__":
    sample_code = """
import os

DB_HOST = "localhost"
DEMO_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
DEMO_PASSWORD = "MySuperSecretPassword123!"
DEMO_RANDOM_TOKEN = "x9K2mP8vL4nQ7wR3zT6yB1cF5hJ0dG8s"
"""
    results = scan_text(sample_code)
    if not results:
        print("No secrets found.")
    else:
        for item in results:
            print(
                f"[Line {item['line']}] {item['type']} -> {item['snippet']} ({item['reason']})"
            )