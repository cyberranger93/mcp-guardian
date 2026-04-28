# Security Policy

## Supported Versions

MCP Guardian is pre-1.0. Security fixes are released on the latest published version.

## Reporting A Vulnerability

Please report vulnerabilities privately. Do not open a public issue with exploit details, secrets, or proof-of-concept payloads.

Send a report with:

- Affected version or commit.
- Environment details.
- Steps to reproduce.
- Expected and actual behavior.
- Impact assessment.
- Any relevant logs with secrets removed.

If a private security advisory channel is available on the repository, use it. Otherwise, contact the project maintainers directly.

## Scope

In scope:

- Policy bypasses that allow blocked MCP tool calls.
- Secret redaction failures.
- Audit log leakage of sensitive values.
- Scanner false negatives for high-confidence risky patterns.
- Command injection or path traversal in Guardian itself.

Out of scope:

- Malicious MCP server behavior outside the proxied MCP protocol.
- Vulnerabilities caused by intentionally permissive local policy.
- Issues requiring full compromise of the host machine.
- Denial-of-service findings without a security impact.

## Safe Handling

Do not include live tokens, private keys, internal hostnames, or customer data in reports. Use synthetic examples where possible.
