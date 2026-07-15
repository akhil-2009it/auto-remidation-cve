# vulnerable-rn-app

Intentionally vulnerable demo app.

## Vulnerability

`axios@0.21.1` — CVE-2023-45857 (HIGH). See `xray-report.json`.

## Peer conflict

`react-native-svg-charts@5.4.0` declares `axios: ^0.21.0` as peer.
Direct bump to `axios@1.6.7` → `ERESOLVE`.

Run `fix-tool` in the sibling folder to auto-remediate.
