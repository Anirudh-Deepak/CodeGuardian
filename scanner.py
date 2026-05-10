import os
from rules import detect_secrets


def mask_secret(value):
    if len(value) <= 6:
        return "****"
    return value[:3] + "****" + value[-3:]


def scan_file(file_path):

    findings = []
    seen = set()
    counts = {}

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):

            detected = detect_secrets(line)

            for item in detected:

                secret_type = item["type"]
                value = item["value"]

                key = (secret_type, value)

                if key not in seen:
                    seen.add(key)
                    counts[key] = 1

                    findings.append({
                        "file": file_path,
                        "line": line_number,
                        "type": secret_type,
                        "code": line.strip(),
                        "value": mask_secret(value),
                        "raw_value": value,
                        "occurrences": 1
                    })

                else:
                    counts[key] += 1

                    for f in findings:
                        if f["type"] == secret_type and f["raw_value"] == value:
                            f["occurrences"] = counts[key]

    except Exception as e:
        print(f"Error scanning {file_path}: {e}")

    return findings


def scan_directory(folder_path):

    supported_extensions = [".py", ".js", ".java", ".c", ".cpp"]

    all_findings = []
    seen = set()

    for root, dirs, files in os.walk(folder_path):

        for file in files:

            if any(file.endswith(ext) for ext in supported_extensions):

                file_path = os.path.join(root, file)

                results = scan_file(file_path)

                for item in results:

                    key = (item["type"], item["raw_value"])

                    if key not in seen:
                        seen.add(key)
                        all_findings.append(item)

                    else:
                        for f in all_findings:
                            if f["type"] == item["type"] and f["raw_value"] == item["raw_value"]:
                                f["occurrences"] += 1

    return all_findings