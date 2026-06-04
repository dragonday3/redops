# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately to: **ai@globalvoxinc.com**

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You can expect an acknowledgement within **48 hours** and a resolution timeline within **7 days** for confirmed issues.

## Scope

Security reports are welcome for:
- Vulnerabilities in redops itself (code execution, path traversal, injection, etc.)
- Issues in the Docker image or CI/CD configuration
- API endpoint security issues (authentication bypass, data leakage)
- Dependency vulnerabilities with direct exploitability

## Authorized Use Only

redops is a **management layer** for authorized red team engagements. It contains no C2 infrastructure, implants, exploit delivery, or offensive payloads. It is designed to help operators document and manage engagements they are **explicitly authorized** to conduct.

The maintainers are not responsible for unauthorized, illegal, or unethical use of this software. Always obtain written authorization before conducting any security assessment.
