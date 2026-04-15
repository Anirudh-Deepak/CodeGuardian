SEVERITY_LEVELS = {

    "API Key": "HIGH",
    "Password": "MEDIUM",
    "Access Token": "HIGH",
    "AWS Access Key": "CRITICAL",
    "Private Key": "CRITICAL",
    "Database URL": "HIGH",
    "JWT Token": "MEDIUM"

}

RECOMMENDATIONS = {

    "API Key": "Store API keys in environment variables instead of source code.",

    "Password": "Avoid hardcoding passwords. Use secure configuration or secret managers.",

    "Access Token": "Tokens should be stored securely using environment variables or vault systems.",

    "AWS Access Key": "Use IAM roles instead of embedding keys.",

    "Private Key": "Never expose private keys in source code.",

    "Database URL": "Move database credentials to environment variables.",

    "JWT Token": "JWT tokens should not be hardcoded."
}


def analyze_findings(findings):

    analyzed_results = []

    for finding in findings:

        secret_type = finding["type"]

        severity = SEVERITY_LEVELS.get(secret_type, "LOW")

        recommendation = RECOMMENDATIONS.get(secret_type, "Review this secret.")

        finding["severity"] = severity
        finding["recommendation"] = recommendation

        analyzed_results.append(finding)

    return analyzed_results