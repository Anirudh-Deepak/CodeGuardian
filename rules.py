import re

SECRET_PATTERNS = {

    "API Key": r"(?i)api[_-]?key\s*=\s*['\"].+['\"]",

    "Password": r"(?i)password\s*=\s*['\"].+['\"]",

    "Access Token": r"(?i)token\s*=\s*['\"].+['\"]",

    "AWS Access Key": r"AKIA[0-9A-Z]{16}",

    "Private Key": r"-----BEGIN PRIVATE KEY-----",

    "Database URL": r"(?i)(mongodb|mysql|postgres):\/\/[^\s]+",

    "JWT Token": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
}


def detect_secrets(code_line):

    findings = []

    for secret_type, pattern in SECRET_PATTERNS.items():
        if re.search(pattern, code_line):
            findings.append(secret_type)

    return findings