# Security policy

## Supported versions

Security fixes are provided for the latest published release.

## Reporting a vulnerability

Please do not disclose security vulnerabilities in a public issue. Use the
repository owner's private contact method or GitHub's private vulnerability
reporting feature. Include affected versions, reproduction steps and the
potential impact.

API secrets must be stored in protected Icinga Director fields. Run the check
with a dedicated OPNsense user that has only the required read privileges.
