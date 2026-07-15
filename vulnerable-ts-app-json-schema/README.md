# vulnerable-ts-app-json-schema

**Intentionally vulnerable** — introduces `CVE-2021-3918` (CVSS 9.8) in `json-schema@0.2.3`.

## Vulnerability

Prototype pollution in json-schema allows arbitrary Object.prototype writes via a crafted schema.

- Vulnerable range: `<0.4.0`
- Fixed range: `>=0.4.0`
- Recommended: `0.4.0`
- Reference: https://nvd.nist.gov/vuln/detail/CVE-2021-3918

See `src/index.ts` for the exploitable code path and `xray-report.json` for the scanner output.

To auto-remediate: run `fix-tool/batch_remediate.py vulnerable-ts-app-json-schema` from repo root.
