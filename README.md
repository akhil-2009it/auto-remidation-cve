# vuln-demo — Claude-powered dependency remediation

Interactive TUI that reads a JFrog Xray finding, reasons about the peer-dep
conflict with Claude, applies the fix, and creates a git branch + PR body —
all one keypress.

## Layout

```
vuln-demo/
├── vulnerable-app/          # RN app w/ axios@0.21.1 (CVE-2023-45857)
│   ├── package.json         # axios 0.21.1 + react-native-svg-charts 5.4.0 (peer axios ^0.21.0)
│   ├── src/index.js         # code path that triggers the SSRF-adjacent bug
│   └── xray-report.json     # simulated scanner output
└── fix-tool/                # Python + Textual + Anthropic SDK
    ├── remediator.py        # engine: parse finding → detect conflict → ask Claude → patch
    ├── tui.py               # Textual UI, [F] fix / [C] commit
    ├── registry_stubs/      # offline npm metadata for reproducible demo
    ├── requirements.txt
    └── .env.example
```

## Scenario (the "unsolvable-by-naive-bump" case)

- `axios@0.21.1` → **CVE-2023-45857** (HIGH). Fix requires `>=1.6.0`.
- Bumping directly → **ERESOLVE**: `react-native-svg-charts@5.4.0` peer requires `axios: ^0.21.0`.
- Tool queries registry → finds `react-native-svg-charts@6.0.0` accepts `axios: ^1.6.0`.
- Claude picks strategy `coordinated_upgrade`, patches both, writes PR body.

## Run

```bash
make setup                   # venv + deps + .env scaffold
$EDITOR fix-tool/.env        # set ANTHROPIC_API_KEY
make demo                    # launch TUI
```

Inside the TUI:

| Key | Action |
|---|---|
| `F` | Run remediation (Claude call → patch package.json) |
| `C` | Commit patch + PR body to `fix/<cve>-<pkg>` branch |
| `R` | Reload findings from `xray-report.json` |
| `Q` | Quit |

## What Claude actually reasons about

`remediator.py:SYSTEM_PROMPT` — strategy priority:

1. **safe_minor_bump** — vuln pkg has a patch inside peer range + outside vuln range.
2. **coordinated_upgrade** — bump vuln pkg *and* the blocker together.
3. **nested_isolation** — allow duplicate nested version if reachability-safe.
4. **escalate** — flag for human, no PR.

Model returns strict JSON; anything ambiguous → `requires_human: true` and no
files are touched.

## Design notes

- No `--legacy-peer-deps` shortcut — the whole point is to avoid the silent
  runtime break.
- Registry lookups are stubbed for `react-native-svg-charts` so the demo is
  deterministic offline; other packages hit npm live.
- The tool never runs `npm install`. It resolves the conflict at the manifest
  level, then hands off to CI/regression for validation (Step 6 in the PRD).
