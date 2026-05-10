import re
from entropy import is_high_entropy

SECRET_PATTERNS = {
    "API Key": r"(?i)(api[_-]?key|secret[_-]?key|client[_-]?key)\s*=\s*['\"](.+?)['\"]",
    "Password": r"(?i)password\s*=\s*['\"](.+?)['\"]",
    "Access Token": r"(?i)token\s*=\s*['\"](.+?)['\"]",
    "AWS Access Key": r"(AKIA[0-9A-Z]{16})",
    "Private Key": r"-----BEGIN[\s\S]*PRIVATE KEY-----",
    "Database URL": r"((mongodb|mysql|postgres):\/\/[^\s]+)",
    "JWT Token": r"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
}

GENERIC_PATTERN = r"['\"]([A-Za-z0-9_\-]{20,})['\"]"


def detect_secrets(code_line):

    findings = []
    detected_values = set()  

    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, code_line)

        for match in matches:
            value = match[1] if isinstance(match, tuple) else match

            if value not in detected_values:
                findings.append({
                    "type": secret_type,
                    "value": value
                })

                detected_values.add(value)

    generic_matches = re.findall(GENERIC_PATTERN, code_line)

    for value in generic_matches:

        if value in detected_values:
            continue
        
        if is_high_entropy(value):
            findings.append({
                "type": "Potential Secret",
                "value": value
            })

            detected_values.add(value)

    return findings