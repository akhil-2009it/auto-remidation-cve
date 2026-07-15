# vulnerable-ts-app-json5

**Intentionally vulnerable** — introduces `CVE-2022-46175` (CVSS 9.8) in `json5@2.2.0`.

## Vulnerability

json5.parse mutates Object.prototype when input contains __proto__ keys.

- Vulnerable range: `<2.2.2`
- Fixed range: `>=2.2.2`
- Recommended: `2.2.3`
- Reference: https://nvd.nist.gov/vuln/detail/CVE-2022-46175

See `src/index.ts` for the exploitable code path and `xray-report.json` for the scanner output.

To auto-remediate: run `fix-tool/batch_remediate.py vulnerable-ts-app-json5` from repo root.
