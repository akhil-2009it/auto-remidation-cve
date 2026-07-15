"""Create 5 branches, each introducing ONE vulnerable TS CVE, then open 5 PRs.

Each branch adds a minimal vulnerable-ts-app-<cve>/ with:
  - package.json  (single vulnerable dep pinned at exploitable version)
  - src/index.ts  (code path that exercises the CVE)
  - xray-report.json  (that one finding)
  - README.md

No fixes here — this deliberately introduces vulnerabilities so a later
fix-tool run can remediate them each into their own PR.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class CVEDef:
    cve: str
    package: str
    current_version: str
    vulnerable_range: str
    fixed_range: str
    recommended_version: str
    summary: str
    reference: str
    code_snippet: str  # TS body demonstrating the vulnerable usage
    imports: str


CVES: list[CVEDef] = [
    CVEDef(
        cve="CVE-2021-3918",
        package="json-schema",
        current_version="0.2.3",
        vulnerable_range="<0.4.0",
        fixed_range=">=0.4.0",
        recommended_version="0.4.0",
        summary="Prototype pollution in json-schema allows arbitrary Object.prototype writes via a crafted schema.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-3918",
        imports='import * as jsonSchema from "json-schema";',
        code_snippet=(
            "// CVE-2021-3918: json-schema prototype pollution.\n"
            "// Attacker-supplied schema can pollute Object.prototype.\n"
            "export function validateSchema(untrustedSchema: any, data: any): boolean {\n"
            "  const result: any = (jsonSchema as any).validate(data, untrustedSchema);\n"
            "  return result.valid;\n"
            "}\n"
        ),
    ),
    CVEDef(
        cve="CVE-2022-46175",
        package="json5",
        current_version="2.2.0",
        vulnerable_range="<2.2.2",
        fixed_range=">=2.2.2",
        recommended_version="2.2.3",
        summary="json5.parse mutates Object.prototype when input contains __proto__ keys.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2022-46175",
        imports='import JSON5 from "json5";',
        code_snippet=(
            "// CVE-2022-46175: json5 prototype pollution via __proto__ keys.\n"
            "export function parseUserConfig(rawJson5: string): any {\n"
            "  return JSON5.parse(rawJson5);\n"
            "}\n"
        ),
    ),
    CVEDef(
        cve="CVE-2022-25878",
        package="protobufjs",
        current_version="6.11.2",
        vulnerable_range="<6.11.3",
        fixed_range=">=6.11.3",
        recommended_version="6.11.4",
        summary="protobufjs util.setProperty is missing prototype-key checks, enabling prototype pollution.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2022-25878",
        imports='import * as protobuf from "protobufjs";',
        code_snippet=(
            "// CVE-2022-25878: protobufjs prototype pollution via util.setProperty.\n"
            "export function decodeMessage(descriptor: string, buf: Uint8Array): any {\n"
            "  const root = protobuf.parse(descriptor).root;\n"
            '  const Msg = root.lookupType("demo.Msg");\n'
            "  return Msg.decode(buf);\n"
            "}\n"
        ),
    ),
    CVEDef(
        cve="CVE-2021-44906",
        package="minimist",
        current_version="1.2.5",
        vulnerable_range="<1.2.6",
        fixed_range=">=1.2.6",
        recommended_version="1.2.8",
        summary="minimist prototype pollution via crafted --__proto__ argv keys.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-44906",
        imports='import minimist from "minimist";',
        code_snippet=(
            "// CVE-2021-44906: minimist prototype pollution via --__proto__ argv.\n"
            "export function parseCliArgs(argv: string[]): any {\n"
            "  return minimist(argv);\n"
            "}\n"
        ),
    ),
    CVEDef(
        cve="CVE-2022-37601",
        package="loader-utils",
        current_version="2.0.2",
        vulnerable_range="<2.0.3",
        fixed_range=">=2.0.3",
        recommended_version="2.0.4",
        summary="loader-utils parseQuery is vulnerable to prototype pollution via crafted url query strings.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2022-37601",
        imports='import * as loaderUtils from "loader-utils";',
        code_snippet=(
            "// CVE-2022-37601: loader-utils prototype pollution via parseQuery.\n"
            "export function extractQueryOptions(loaderRequest: string): any {\n"
            "  return (loaderUtils as any).parseQuery(loaderRequest);\n"
            "}\n"
        ),
    ),
]


def run(cmd: list[str], cwd: Path = REPO_ROOT) -> str:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}\nSTDERR: {r.stderr}")
    return r.stdout


def build_app_dir(cve: CVEDef) -> Path:
    """Write the vulnerable-ts-app-<pkg>/ tree for one CVE."""
    app_name = f"vulnerable-ts-app-{cve.package}"
    app_dir = REPO_ROOT / app_name
    (app_dir / "src").mkdir(parents=True, exist_ok=True)

    pkg = {
        "name": app_name,
        "version": "1.0.0",
        "description": f"Intentionally vulnerable TS app: {cve.cve} in {cve.package}",
        "main": "src/index.ts",
        "scripts": {"build": "tsc"},
        "dependencies": {cve.package: cve.current_version},
        "devDependencies": {"typescript": "^5.3.0"},
    }
    (app_dir / "package.json").write_text(json.dumps(pkg, indent=2) + "\n")

    ts = (
        "// Intentionally vulnerable demo — DO NOT DEPLOY\n"
        f"// {cve.cve} ({cve.package}@{cve.current_version}) — CVSS 9.8\n\n"
        f"{cve.imports}\n\n"
        f"{cve.code_snippet}"
    )
    (app_dir / "src" / "index.ts").write_text(ts)

    tsconfig = {
        "compilerOptions": {
            "target": "ES2020",
            "module": "commonjs",
            "esModuleInterop": True,
            "strict": True,
            "outDir": "dist",
            "skipLibCheck": True,
        },
        "include": ["src/**/*.ts"],
    }
    (app_dir / "tsconfig.json").write_text(json.dumps(tsconfig, indent=2) + "\n")

    xray = {
        "scanner": "jfrog-xray",
        "scanned_at": "2026-07-15T09:00:00Z",
        "project": app_name,
        "findings": [
            {
                "id": f"XRAY-{cve.cve}",
                "cve": cve.cve,
                "severity": "CRITICAL",
                "cvss": 9.8,
                "package": cve.package,
                "ecosystem": "npm",
                "current_version": cve.current_version,
                "vulnerable_range": cve.vulnerable_range,
                "fixed_range": cve.fixed_range,
                "recommended_version": cve.recommended_version,
                "summary": cve.summary,
                "references": [cve.reference],
            }
        ],
    }
    (app_dir / "xray-report.json").write_text(json.dumps(xray, indent=2) + "\n")

    readme = (
        f"# {app_name}\n\n"
        f"**Intentionally vulnerable** — introduces `{cve.cve}` "
        f"(CVSS 9.8) in `{cve.package}@{cve.current_version}`.\n\n"
        f"## Vulnerability\n\n{cve.summary}\n\n"
        f"- Vulnerable range: `{cve.vulnerable_range}`\n"
        f"- Fixed range: `{cve.fixed_range}`\n"
        f"- Recommended: `{cve.recommended_version}`\n"
        f"- Reference: {cve.reference}\n\n"
        f"See `src/index.ts` for the exploitable code path and "
        f"`xray-report.json` for the scanner output.\n\n"
        f"To auto-remediate: run `fix-tool/batch_remediate.py {app_name}` "
        f"from repo root.\n"
    )
    (app_dir / "README.md").write_text(readme)

    return app_dir


def process(cve: CVEDef, idx: int, total: int) -> tuple[str, str] | None:
    branch = f"cve/{cve.cve.lower()}-{cve.package}"
    print(f"\n{'=' * 60}")
    print(f"[{idx}/{total}] {cve.cve} — introduce {cve.package}@{cve.current_version}")
    print(f"{'=' * 60}")

    run(["git", "checkout", "main"])
    run(["git", "checkout", "-B", branch])
    app_dir = build_app_dir(cve)
    run(["git", "add", "-A"])
    run(
        [
            "git",
            "-c",
            "user.name=akhil",
            "-c",
            "user.email=akhil@local",
            "commit",
            "-m",
            f"vuln: introduce {cve.cve} — {cve.package}@{cve.current_version}",
        ]
    )
    run(["git", "push", "-u", "origin", branch, "--force"])

    body = (
        f"## Introduce {cve.cve} — CVSS 9.8 (CRITICAL)\n\n"
        f"**Package:** `{cve.package}@{cve.current_version}`\n"
        f"**Vulnerable range:** `{cve.vulnerable_range}`\n"
        f"**Fixed in:** `{cve.recommended_version}` (`{cve.fixed_range}`)\n\n"
        f"### Summary\n\n{cve.summary}\n\n"
        f"### Reference\n\n{cve.reference}\n\n"
        f"### What this PR does\n\n"
        f"- Adds `{app_dir.name}/` with a minimal reproducer for {cve.cve}\n"
        f"- Pins `{cve.package}` at the vulnerable version `{cve.current_version}`\n"
        f"- Ships `xray-report.json` with the scanner finding\n\n"
        f"### DO NOT MERGE AS-IS\n\n"
        f"This PR **intentionally introduces a vulnerability** for auto-remediation "
        f"testing. Follow up by running the fix-tool against this branch:\n\n"
        f"```\nfix-tool/batch_remediate.py {app_dir.name}\n```\n\n"
        f"The remediation PR will bump to `{cve.recommended_version}`.\n"
    )
    body_file = REPO_ROOT / ".pr_body.md"
    body_file.write_text(body)

    title = f"vuln: introduce {cve.cve} in {cve.package}"
    pr = subprocess.run(
        [
            "gh",
            "pr",
            "create",
            "--base",
            "main",
            "--head",
            branch,
            "--title",
            title,
            "--body-file",
            str(body_file),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    body_file.unlink(missing_ok=True)

    if pr.returncode != 0:
        if "already exists" in pr.stderr:
            view = subprocess.run(
                ["gh", "pr", "view", branch, "--json", "url", "-q", ".url"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
            )
            url = view.stdout.strip()
            print(f"[ok] PR already exists: {url}")
            return (branch, url)
        print(f"[error] gh pr create failed: {pr.stderr}")
        return None

    url = pr.stdout.strip()
    print(f"[ok] PR opened: {url}")
    return (branch, url)


def main() -> None:
    results: list[tuple[str, str]] = []
    for i, cve in enumerate(CVES, 1):
        r = process(cve, i, len(CVES))
        if r:
            results.append(r)

    run(["git", "checkout", "main"])

    print(f"\n{'=' * 60}")
    print(f"SUMMARY: {len(results)} / {len(CVES)} PRs opened")
    print(f"{'=' * 60}")
    for branch, url in results:
        print(f"  {branch:45s}  {url}")


if __name__ == "__main__":
    main()
