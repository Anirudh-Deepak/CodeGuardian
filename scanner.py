import os
from rules import detect_secrets


def scan_file(file_path):

    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):

            detected = detect_secrets(line)

            for secret in detected:
                findings.append({
                    "file": file_path,
                    "line": line_number,
                    "type": secret,
                    "code": line.strip()
                })

    except Exception as e:
        print(f"Error scanning {file_path}: {e}")

    return findings


def scan_directory(folder_path):

    supported_extensions = [".py", ".js", ".java", ".c", ".cpp"]

    all_findings = []

    for root, dirs, files in os.walk(folder_path):

        for file in files:

            if any(file.endswith(ext) for ext in supported_extensions):

                file_path = os.path.join(root, file)

                results = scan_file(file_path)

                all_findings.extend(results)

    return all_findings