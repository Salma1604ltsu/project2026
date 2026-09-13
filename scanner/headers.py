EXPECTED_HEADERS = {
    "Content-Security-Policy": ("high", "Helps restrict executable content and reduce XSS impact."),
    "Strict-Transport-Security": ("medium", "Requests browsers to prefer HTTPS for the site."),
    "X-Content-Type-Options": ("low", "Reduces MIME-type sniffing risks."),
    "X-Frame-Options": ("medium", "Helps prevent clickjacking in older browser controls."),
    "Referrer-Policy": ("low", "Controls how much referrer information is sent."),
    "Permissions-Policy": ("low", "Restricts access to selected browser capabilities."),
}


def analyze_headers(headers):
    normalized = {k.lower(): v for k, v in headers.items()}
    findings = []
    for header, (severity, description) in EXPECTED_HEADERS.items():
        if header.lower() not in normalized:
            findings.append({
                "category": "Security Headers",
                "title": f"Missing {header}",
                "severity": severity,
                "description": description,
                "recommendation": f"Configure the {header} response header with a policy appropriate for the application.",
            })
    server = normalized.get("server")
    if server:
        findings.append({
            "category": "Information Disclosure",
            "title": "Server header is exposed",
            "severity": "low",
            "description": f"The response identifies the server as {server}.",
            "recommendation": "Minimize unnecessary server/version disclosure where practical.",
        })
    return findings
