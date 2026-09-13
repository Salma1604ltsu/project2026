from scanner.headers import analyze_headers
from scanner.risk_score import calculate_score


def test_missing_security_headers_are_reported():
    findings = analyze_headers({"Server": "Example"})
    titles = {f["title"] for f in findings}
    assert "Missing Content-Security-Policy" in titles
    assert "Server header is exposed" in titles


def test_risk_score_is_bounded():
    findings = [{"severity": "critical"}] * 10
    score, level = calculate_score(findings)
    assert score == 100
    assert level == "Critical"
