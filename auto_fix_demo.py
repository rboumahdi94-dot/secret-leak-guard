import math
import re


def calculate_entropy(data: str) -> float:
   
    if not data:
        return 0.0
    length = len(data)
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1

    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def sanitize_env_name(name: str, index: int) -> str:
   
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    if not cleaned:
        cleaned = "DETECTED_SECRET"
    return f"{cleaned}_{index}"


def auto_fix_secrets(content: str, entropy_threshold: float = 4.2) -> dict:
    
    env_entries = {}
    secret_counter = 1
    fixed_lines = []

   
    assignment_regex = re.compile(
        r"^(\s*)([A-Za-z0-9_]*(?:password|passwd|secret|api_key|apikey|token)[A-Za-z0-9_]*)\s*=\s*(['\"])([^'\"]{6,})\3(.*)$",
        re.IGNORECASE,
    )

   
    token_regex = re.compile(r"[A-Za-z0-9_\-+/=]{16,}")

    for line in content.splitlines():
        assign_match = assignment_regex.match(line)
        if assign_match:
            indent, var_name, _, secret_value, trailing = assign_match.groups()
            env_key = sanitize_env_name(var_name, secret_counter)
            secret_counter += 1

            env_entries[env_key] = secret_value
            fixed_lines.append(f'{indent}{var_name} = os.getenv("{env_key}"){trailing}')
            continue

       
        def replace_high_entropy(match):
            nonlocal secret_counter
            candidate = match.group(0)
            if calculate_entropy(candidate) >= entropy_threshold:
                env_key = sanitize_env_name("SECRET", secret_counter)
                secret_counter += 1
                env_entries[env_key] = candidate
                return f'os.getenv("{env_key}")'
            return candidate

        new_line = token_regex.sub(replace_high_entropy, line)
        fixed_lines.append(new_line)

  
    fixed_code = "\n".join(fixed_lines)
    if env_entries and "import os" not in fixed_code:
        fixed_code = "import os\n\n" + fixed_code

    
    env_content = "\n".join(f"{key}={value}" for key, value in env_entries.items())
    if env_content:
        env_content += "\n"

    return {
        "fixed_code": fixed_code,
        "env_content": env_content,
        "secrets_count": len(env_entries),
    }


if __name__ == "__main__":
    sample_code = """DB_HOST = "localhost"
OPENAI_API_KEY = "sk-demo1234567890abcdef1234567890"
DB_PASSWORD = "SuperSecretDemoPassword99"
STANDALONE_TOKEN = "x9K2mP8vL4nQ7wR3zT6yB1cF5hJ0dG8s"
"""

    result = auto_fix_secrets(sample_code)

    print("=== Cleaned Code ===")
    print(result["fixed_code"])

    print("=== Generated .env ===")
    print(result["env_content"])

   
    with open("cleaned_app.py", "w", encoding="utf-8") as f:
        f.write(result["fixed_code"])

    with open(".env", "w", encoding="utf-8") as f:
        f.write(result["env_content"])

    print(f"Done. Replaced {result['secrets_count']} secret(s).")