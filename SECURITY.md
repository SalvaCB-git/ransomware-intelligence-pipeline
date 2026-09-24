# Security Policy

## Supported code

Security fixes target the default branch and the currently deployed read-only
demo. Historical commits and local research environments are not maintained as
separate supported releases.

## Reporting a vulnerability

Please do not disclose a vulnerability, credential, personal data or working
exploit in a public issue.

Use GitHub's private vulnerability reporting flow under **Security → Advisories
→ Report a vulnerability** when it is available. Otherwise, contact the
maintainer by opening a public issue that contains no vulnerability details and
asks only to establish a private reporting channel.

A useful report includes:

- the affected component or endpoint;
- clear reproduction steps;
- the observed and expected behavior;
- the likely impact;
- suggested remediation, if known.

The maintainer will acknowledge a reproducible report, investigate its impact
and coordinate remediation before public disclosure.

## Live demo authorization

The public demo is provided for normal, read-only evaluation. Authorization does
not extend to mutation endpoints, credential testing, denial-of-service testing,
automated scanning, bypass attempts or access to infrastructure behind the
application.

If you believe the demo exposes sensitive information, stop testing and report
the observation privately.

## Secrets and personal data

- Never commit API keys, passwords, tokens or populated `.env` files.
- Use the supplied `.env.example` files as templates.
- Do not attach the full-text research corpus or personal data to issues.
- Revoke and rotate a secret immediately if accidental exposure is suspected.
