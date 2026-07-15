# vulnerable-ts-app-protobufjs

**Intentionally vulnerable** — introduces `CVE-2022-25878` (CVSS 9.8) in `protobufjs@6.11.2`.

## Vulnerability

protobufjs util.setProperty is missing prototype-key checks, enabling prototype pollution.

- Vulnerable range: `<6.11.3`
- Fixed range: `>=6.11.3`
- Recommended: `6.11.4`
- Reference: https://nvd.nist.gov/vuln/detail/CVE-2022-25878

See `src/index.ts` for the exploitable code path and `xray-report.json` for the scanner output.

To auto-remediate: run `fix-tool/batch_remediate.py vulnerable-ts-app-protobufjs` from repo root.
