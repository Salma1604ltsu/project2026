from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import requests


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class APISecurityScanner:
    """Non-destructive API security assessment engine."""

    def __init__(self, timeout: float = 8.0, verify_tls: bool = True,
                 allow_private_targets: bool | None = None) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.allow_private_targets = (
            os.getenv("ALLOW_PRIVATE_TARGETS") == "1"
            if allow_private_targets is None else allow_private_targets
        )

    def validate_target(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Target must be a valid HTTP(S) URL.")
        if self.allow_private_targets:
            return
        try:
            addresses = {x[4][0] for x in socket.getaddrinfo(parsed.hostname, None)}
        except socket.gaierror as exc:
            raise ValueError(f"Unable to resolve target host: {exc}") from exc
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                raise ValueError(
                    "Private/local targets are blocked by default. "
                    "Set ALLOW_PRIVATE_TARGETS=1 only for an authorized lab."
                )

    def request(self, url: str, *, token: str | None = None,
                method: str = "GET") -> requests.Response:
        self.validate_target(url)
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError("Only GET, HEAD and OPTIONS are enabled by default.")
        headers = {
            "Accept": "application/json, */*",
            "User-Agent": "WebGuard-API-Security-Tool/1.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = requests.request(
            method, url, headers=headers, timeout=self.timeout,
            allow_redirects=False, verify=self.verify_tls
        )
        if 300 <= response.status_code < 400 and response.headers.get("Location"):
            self.validate_target(requests.compat.urljoin(url, response.headers["Location"]))
        return response

    def check_authentication(self, url: str, token: str | None = None) -> list[Finding]:
        try:
            unauth = self.request(url)
            auth = self.request(url, token=token) if token else None
        except requests.RequestException as exc:
            return [Finding("authentication", "INFO", "Authentication check could not complete",
                            str(exc), "Retry from an authorized environment.")]

        findings: list[Finding] = []
        if unauth.status_code in {401, 403}:
            findings.append(Finding(
                "authentication", "INFO", "Endpoint rejects unauthenticated access",
                f"Unauthenticated response: HTTP {unauth.status_code}.",
                "Keep authentication enforced on protected endpoints."
            ))
        elif unauth.status_code < 400:
            findings.append(Finding(
                "authentication", "MEDIUM", "Endpoint is accessible without credentials",
                f"Unauthenticated request returned HTTP {unauth.status_code}.",
                "Confirm the endpoint is intentionally public. Protect sensitive resources."
            ))
        else:
            findings.append(Finding(
                "authentication", "INFO", "Unauthenticated request did not prove bypass",
                f"Unauthenticated response: HTTP {unauth.status_code}.",
                "Review application-specific authentication requirements manually."
            ))

        if auth is not None and auth.status_code in {401, 403}:
            findings.append(Finding(
                "authentication", "INFO", "Supplied token was rejected",
                f"Authenticated request returned HTTP {auth.status_code}.",
                "Verify the token is valid and has access to this endpoint."
            ))
        return findings

    def check_headers(self, response: requests.Response) -> list[Finding]:
        h = {k.lower(): v for k, v in response.headers.items()}
        findings: list[Finding] = []
        for name in ("x-content-type-options", "content-security-policy"):
            if name not in h:
                findings.append(Finding(
                    "headers", "LOW", f"Missing {name}",
                    "Response does not include this security-related header.",
                    f"Review whether {name} is appropriate for the API response."
                ))
        if response.url.startswith("https://") and "strict-transport-security" not in h:
            findings.append(Finding(
                "headers", "LOW", "Missing Strict-Transport-Security",
                "HTTPS response lacks HSTS.",
                "Consider HSTS where HTTPS is enforced for the service."
            ))
        if h.get("access-control-allow-origin") == "*":
            findings.append(Finding(
                "cors", "MEDIUM", "Wildcard CORS origin",
                "Access-Control-Allow-Origin is '*'.",
                "Restrict browser origins when the API handles sensitive or authenticated data."
            ))
        if "server" in h:
            findings.append(Finding(
                "information-disclosure", "INFO", "Server banner exposed",
                h["server"], "Minimize unnecessary software/version disclosure."
            ))
        return findings

    def check_content_type(self, response: requests.Response) -> list[Finding]:
        content_type = response.headers.get("Content-Type", "").lower()
        body = response.text[:1000].lstrip()
        if (body.startswith("{") or body.startswith("[")) and "json" not in content_type:
            return [Finding(
                "content-type", "LOW", "JSON-like response without JSON content type",
                f"Content-Type: {content_type or '(missing)'}",
                "Return JSON with an application/json content type."
            )]
        return []

    def check_error_handling(self, response: requests.Response) -> list[Finding]:
        if response.status_code < 400:
            return []
        body = response.text[:2000].lower()
        markers = ("traceback", "stack trace", "exception:", "sqlstate",
                   "syntax error", "debug=true")
        if any(m in body for m in markers):
            return [Finding(
                "error-handling", "MEDIUM", "Potential verbose error disclosure",
                f"HTTP {response.status_code} response contains debug/error markers.",
                "Return generic client errors and keep stack traces out of production responses."
            )]
        return []

    def check_rate_limit(self, url: str, token: str | None = None,
                         samples: int = 3) -> list[Finding]:
        samples = max(1, min(samples, 5))
        responses: list[requests.Response] = []
        try:
            for _ in range(samples):
                responses.append(self.request(url, token=token))
        except requests.RequestException as exc:
            return [Finding("rate-limit", "INFO", "Rate-limit check could not complete",
                            str(exc), "Retry from an authorized test environment.")]
        advertised = {}
        for response in responses:
            for key, value in response.headers.items():
                if "rate" in key.lower() or key.lower() == "retry-after":
                    advertised[key] = value
        if advertised:
            return [Finding(
                "rate-limit", "INFO", "Rate-limit headers observed",
                "; ".join(f"{k}: {v}" for k, v in advertised.items()),
                "Confirm limits are appropriate for the endpoint and authenticated role."
            )]
        if all(r.status_code < 429 for r in responses):
            return [Finding(
                "rate-limit", "LOW", "No rate-limit response signal observed",
                f"{len(responses)} small-sample requests completed without HTTP 429.",
                "Verify rate limiting independently, especially for authentication and sensitive endpoints."
            )]
        return []

    def compare_authorization(self, url: str, token_a: str, token_b: str) -> list[Finding]:
        try:
            a = self.request(url, token=token_a)
            b = self.request(url, token=token_b)
        except requests.RequestException as exc:
            return [Finding("authorization", "INFO", "Authorization comparison could not complete",
                            str(exc), "Retry with two authorized test principals.")]
        if a.status_code == b.status_code and a.text == b.text:
            return [Finding(
                "authorization", "INFO", "Both principals received the same response",
                f"HTTP {a.status_code}; response bodies matched.",
                "Confirm this is expected for the tested resource."
            )]
        return [Finding(
            "authorization", "INFO", "Authorization behavior differs between principals",
            f"Principal A: HTTP {a.status_code}, {len(a.content)} bytes; "
            f"Principal B: HTTP {b.status_code}, {len(b.content)} bytes.",
            "Manually verify the principals have different expected permissions. "
            "Investigate only if an unauthorized principal can access another user's object."
        )]

    def scan(self, url: str, *, token: str | None = None,
             token_a: str | None = None, token_b: str | None = None,
             samples: int = 3) -> dict[str, Any]:
        response = self.request(url, token=token)
        findings: list[Finding] = []
        findings += self.check_authentication(url, token)
        findings += self.check_headers(response)
        findings += self.check_content_type(response)
        findings += self.check_error_handling(response)
        findings += self.check_rate_limit(url, token, samples)
        if token_a and token_b:
            findings += self.compare_authorization(url, token_a, token_b)
        summary = {level: sum(f.severity == level for f in findings)
                   for level in ("HIGH", "MEDIUM", "LOW", "INFO")}
        return {
            "target": url, "method": "GET",
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type"),
            "findings": [f.to_dict() for f in findings],
            "summary": summary,
        }
