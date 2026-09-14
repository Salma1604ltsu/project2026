"""Non-destructive web security checks for authorized assessments."""

from bs4 import BeautifulSoup
from urllib.parse import urljoin


def analyze_advanced(response):
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    # CORS: flag wildcard access-control exposure as an indicator only.
    if headers.get("access-control-allow-origin", "").strip() == "*":
        findings.append({
            "category": "CORS",
            "title": "Wildcard CORS policy",
            "severity": "medium",
            "description": "The response permits cross-origin requests from any origin.",
            "recommendation": "Restrict Access-Control-Allow-Origin to trusted origins where cross-origin access is required.",
        })

    # Cache control for potentially sensitive pages.
    content_type = headers.get("content-type", "").lower()
    if "text/html" in content_type and "cache-control" not in headers:
        findings.append({
            "category": "Security Configuration",
            "title": "Cache-Control policy is not declared",
            "severity": "low",
            "description": "HTML responses do not explicitly declare cache behavior.",
            "recommendation": "Define an appropriate Cache-Control policy, especially for authenticated or sensitive pages.",
        })

    # Referrer and permissions policy are covered by header checks; inspect HTML for
    # password forms submitted over cleartext HTTP without sending test credentials.
    soup = BeautifulSoup(response.text, "html.parser")
    for form in soup.find_all("form"):
        has_password = form.find("input", attrs={"type": "password"}) is not None
        action = form.get("action") or response.url
        action_url = urljoin(response.url, action)
        if has_password and action_url.lower().startswith("http://"):
            findings.append({
                "category": "Authentication Transport",
                "title": "Password form submits over HTTP",
                "severity": "high",
                "description": "A password input appears to submit to a non-HTTPS URL.",
                "recommendation": "Submit authentication credentials only to HTTPS endpoints.",
            })
            break

    # Passive mixed-content indicator; no active exploitation or browser execution.
    if response.url.lower().startswith("https://"):
        insecure_refs = []
        for tag, attr in (("script", "src"), ("img", "src"), ("link", "href"), ("iframe", "src"), ("form", "action")):
            for element in soup.find_all(tag, **{attr: True}):
                value = element.get(attr, "")
                if isinstance(value, str) and value.lower().startswith("http://"):
                    insecure_refs.append(value)
                    if len(insecure_refs) >= 5:
                        break
            if len(insecure_refs) >= 5:
                break
        if insecure_refs:
            findings.append({
                "category": "Transport Security",
                "title": "Potential mixed-content references",
                "severity": "medium",
                "description": "HTTPS HTML contains references to resources or form actions using HTTP.",
                "recommendation": "Use HTTPS URLs for embedded resources and form actions.",
            })

    return findings
