# vulnerable-ts-app-loader-utils

**Intentionally vulnerable** — introduces `CVE-2022-37601` (CVSS 9.8) in `loader-utils@2.0.2`.

## Vulnerability

loader-utils parseQuery is vulnerable to prototype pollution via crafted url query strings.

- Vulnerable range: `<2.0.3`
- Fixed range: `>=2.0.3`
- Recommended: `2.0.4`
- Reference: https://nvd.nist.gov/vuln/detail/CVE-2022-37601

See `src/index.ts` for the exploitable code path and `xray-report.json` for the scanner output.

To auto-remediate: run `fix-tool/batch_remediate.py vulnerable-ts-app-loader-utils` from repo root.
