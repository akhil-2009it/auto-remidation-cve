# vulnerable-ts-app-minimist

**Intentionally vulnerable** — introduces `CVE-2021-44906` (CVSS 9.8) in `minimist@1.2.5`.

## Vulnerability

minimist prototype pollution via crafted --__proto__ argv keys.

- Vulnerable range: `<1.2.6`
- Fixed range: `>=1.2.6`
- Recommended: `1.2.8`
- Reference: https://nvd.nist.gov/vuln/detail/CVE-2021-44906

See `src/index.ts` for the exploitable code path and `xray-report.json` for the scanner output.

To auto-remediate: run `fix-tool/batch_remediate.py vulnerable-ts-app-minimist` from repo root.
