# API Security Testing Tool

A defensive, non-destructive API security assessment module for WebGuard.

## Checks

- Authentication presence and behavior
- Authorization response comparison using two supplied test tokens
- Security response headers
- CORS indicators
- Small-sample rate-limit signals
- Verbose error/information disclosure indicators
- JSON/content-type consistency

Authorization comparison is conservative. A response difference is reported as an observation for manual validation, not automatically treated as a vulnerability.

## Usage

```bash
python -m api_security_tool --url https://api.example.com/v1/users
```

Authenticated check:

```bash
python -m api_security_tool --url https://api.example.com/v1/users --token "$API_TOKEN"
```

Two-principal authorization comparison:

```bash
python -m api_security_tool \
  --url https://api.example.com/v1/users/123 \
  --token-a "$USER_A_TOKEN" \
  --token-b "$USER_B_TOKEN"
```

JSON output:

```bash
python -m api_security_tool --url https://api.example.com/v1/users --json
```

## Safety

Only assess systems you own or have explicit permission to test. The tool uses GET/HEAD/OPTIONS only and a tiny rate-limit sample. Private/local targets are blocked by default. Set `ALLOW_PRIVATE_TARGETS=1` only for an authorized local lab.

Do not store production tokens in source control or commit them to Git.
