# auto-remediation-cve

> Interactive TUI that turns a JFrog Xray vulnerability finding into a merge-ready fix — with Claude doing the dependency-graph reasoning.

Naive "just bump the version" bots fail the moment a CVE fix collides with a peer-dep range. This tool handles the cascade: it detects the conflict, queries the npm registry for viable resolutions, asks Claude to pick a strategy, applies the patch, and produces a git branch + PR body — all from a single keypress.

---

## The scenario

**Vulnerability:** `axios@0.21.1` — [CVE-2023-45857](https://nvd.nist.gov/vuln/detail/CVE-2023-45857). Fix requires `>= 1.6.0`.

**The conflict:** the app also depends on `react-native-svg-charts@5.4.0`, which declares a peer of `axios: ^0.21.0`. A direct `npm install axios@1.6.7` blows up with `ERESOLVE`. `--legacy-peer-deps` "succeeds" but silently breaks the chart library at runtime.

**How the tool resolves it:**

1. Parse the Xray finding (`xray-report.json`).
2. Walk `package.json` deps; for each, fetch npm metadata and check if `axios` is in its `peerDependencies`.
3. Discover the conflict: `react-native-svg-charts@5.4.0` peer `^0.21.0` doesn't accept `1.6.7`.
4. Search the blocker's version history for a release that accepts fixed axios → finds `6.0.0` with peer `^1.6.0`.
5. Send finding + conflict info to **Claude Opus 4.7** as structured JSON. Claude returns a strategy: `coordinated_upgrade`, `safe_minor_bump`, `nested_isolation`, or `escalate`.
6. Apply the patch to `package.json`, commit to a `fix/<cve>-<pkg>` branch, and write `PR_BODY.md` with full reasoning.

---

## Layout

```
vuln-demo/
├── vulnerable-app/               # RN app with intentional CVE-2023-45857
│   ├── package.json              # axios 0.21.1 + react-native-svg-charts 5.4.0
│   ├── src/index.js              # code path that triggers the SSRF-adjacent bug
│   ├── xray-report.json          # simulated JFrog Xray output
│   └── README.md
│
├── fix-tool/                     # Python engine + Textual TUI
│   ├── remediator.py             # parse → detect conflict → ask Claude → patch → branch
│   ├── tui.py                    # interactive UI (Textual)
│   ├── registry_stubs/           # offline npm metadata for reproducible demo
│   │   └── react-native-svg-charts.json
│   ├── requirements.txt
│   ├── .env.example              # copy → .env, fill in ANTHROPIC_API_KEY
│   └── .env                      # ⚠ gitignored — your key stays local
│
├── Makefile
├── README.md
└── .gitignore
```

---

## Quick start

```bash
make setup                       # venv + deps + scaffold .env
$EDITOR fix-tool/.env            # set ANTHROPIC_API_KEY
make demo                        # launch TUI
```

Inside the TUI:

| Key | Action |
|-----|--------|
| `F` | Run remediation — Claude call → patch `package.json` |
| `C` | Commit patch + `PR_BODY.md` to `fix/<cve>-<pkg>` branch |
| `R` | Reload findings from `xray-report.json` |
| `Q` | Quit |

---

## How Claude decides (strategy priority)

`remediator.py:SYSTEM_PROMPT` asks Claude to return **strict JSON** for one of four strategies, ordered by preference:

1. **`safe_minor_bump`** — a version of the vuln pkg exists inside the peer range *and* outside the vuln range. Cheapest and safest.
2. **`coordinated_upgrade`** — bump both the vuln pkg *and* the blocker together (blocker version must accept fixed pkg). This is what the demo hits.
3. **`nested_isolation`** — allow a duplicate nested copy only if the vulnerable code path is reachability-safe. Flagged as residual risk.
4. **`escalate`** — no safe automated fix; open an issue instead of a PR.

The model returns a strict JSON object; ambiguous outcomes set `requires_human: true` and no files are touched.

---

## Design principles

- **Manifest-level resolution, not `npm install`.** The tool never runs the installer — it edits `package.json` and hands off to CI/regression for actual validation.
- **No `--legacy-peer-deps` shortcut.** The whole point is avoiding silent runtime breakage from forced installs.
- **Deterministic demo.** `react-native-svg-charts` metadata is stubbed in `registry_stubs/` so the demo runs offline. Other packages hit the live npm registry.
- **PR body is the artifact.** Every remediation produces `PR_BODY.md` with: original CVE, why direct bump failed, strategy chosen, residual risks, and validation checklist. Reviewers see reasoning, not just a diff.

---

## Security

- **Never commit `fix-tool/.env`.** It's gitignored. Rotate any key you paste into chat.
- The vulnerable app is intentionally exploitable — do not deploy it.
- Scanner report is fabricated for demo purposes; wire your real Xray/Snyk/Dependabot output into `xray-report.json` to run against production findings.
