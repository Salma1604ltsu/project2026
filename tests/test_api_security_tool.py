from unittest.mock import patch

import pytest
import requests

from api_security_tool.scanner import APISecurityScanner


def make_response(status=200, body='{"ok":true}', headers=None):
    item = requests.Response()
    item.status_code = status
    item._content = body.encode()
    item.headers.update(headers or {"Content-Type": "application/json"})
    item.url = "https://example.com/api/users"
    return item


def test_blocks_private_targets():
    scanner = APISecurityScanner(allow_private_targets=False)
    with patch("api_security_tool.scanner.socket.getaddrinfo",
               return_value=[("", "", "", "", ("127.0.0.1", 0))]):
        with pytest.raises(ValueError):
            scanner.validate_target("https://localhost/api")


def test_detects_wildcard_cors():
    scanner = APISecurityScanner(allow_private_targets=True)
    findings = scanner.check_headers(make_response(headers={
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
    }))
    assert any(f.check == "cors" and f.severity == "MEDIUM" for f in findings)


def test_detects_verbose_error():
    scanner = APISecurityScanner(allow_private_targets=True)
    findings = scanner.check_error_handling(
        make_response(500, "Traceback: Exception: database failed")
    )
    assert any(f.check == "error-handling" for f in findings)


def test_authorization_comparison_is_conservative():
    scanner = APISecurityScanner(allow_private_targets=True)
    with patch.object(scanner, "request", side_effect=[
        make_response(200, '{"id":1}'),
        make_response(403, '{"error":"forbidden"}'),
    ]):
        findings = scanner.compare_authorization(
            "https://example.com/api/users/1", "token-a", "token-b"
        )
    assert findings[0].severity == "INFO"
    assert findings[0].check == "authorization"
