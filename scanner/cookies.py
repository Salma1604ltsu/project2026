def analyze_cookies(response):
    findings = []
    for cookie in response.cookies:
        name = cookie.name
        secure = bool(cookie.secure)
        httponly = cookie.has_nonstandard_attr("HttpOnly")
        samesite = cookie.get_nonstandard_attr("SameSite")

        if not secure and response.url.lower().startswith("https://"):
            findings.append({
                "category": "Cookies",
                "title": f"Cookie {name} lacks Secure flag",
                "severity": "medium",
                "description": "A cookie set over HTTPS does not explicitly require HTTPS transmission.",
                "recommendation": "Set the Secure attribute for cookies that should only travel over HTTPS.",
            })
        if not httponly:
            findings.append({
                "category": "Cookies",
                "title": f"Cookie {name} lacks HttpOnly flag",
                "severity": "medium",
                "description": "Client-side JavaScript may be able to access this cookie.",
                "recommendation": "Set HttpOnly for session or other sensitive cookies that do not need JavaScript access.",
            })
        if not samesite:
            findings.append({
                "category": "Cookies",
                "title": f"Cookie {name} lacks SameSite attribute",
                "severity": "low",
                "description": "The cookie does not explicitly declare a SameSite policy.",
                "recommendation": "Set SameSite=Lax or Strict where compatible with application behavior.",
            })
    return findings
