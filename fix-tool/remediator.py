"""Remediation engine: parse Xray finding -> resolve dep conflict via Claude -> patch + branch."""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import httpx
from anthropic import Anthropic
from packaging.specifiers import SpecifierSet
from packaging.version import Version, InvalidVersion


NPM_REGISTRY = "https://registry.npmjs.org"


@dataclass
class Finding:
    cve: str
    package: str
    current_version: str
    vulnerable_range: str  # npm-style, e.g. "<1.6.0"
    fixed_range: str
    recommended_version: str
    severity: str
    summary: str


@dataclass
class ConflictInfo:
    blocker_pkg: str
    blocker_version: str
    peer_range: str  # e.g. "^0.21.0"
    blocker_versions_available: list[str] = field(default_factory=list)
    compatible_blocker_upgrade: Optional[str] = None  # blocker version that accepts fixed axios


@dataclass
class Strategy:
    kind: str  # "coordinated_upgrade" | "safe_minor_bump" | "nested_isolation" | "escalate"
    rationale: str
    patches: dict  # {"axios": "1.6.7", "react-native-svg-charts": "6.0.0"} or {}
    risk_notes: str
    requires_human: bool = False


@dataclass
class RemediationResult:
    finding: Finding
    conflict: Optional[ConflictInfo]
    strategy: Strategy
    branch: Optional[str]
    pr_body: str
    patched_package_json: Optional[str]


# --- npm registry helpers -----------------------------------------------------

def _npm_semver_to_pep440(spec: str) -> Optional[SpecifierSet]:
    """Best-effort convert npm range like '<1.6.0' or '^0.21.0' to PEP 440.
    Used only for the vulnerable-range check on axios; peer ranges are handled by prompt."""
    spec = spec.strip()
    try:
        if spec.startswith("^"):
            base = Version(spec[1:])
            upper = Version(f"{base.major + 1}.0.0")
            return SpecifierSet(f">={base},<{upper}")
        if spec.startswith("~"):
            base = Version(spec[1:])
            upper = Version(f"{base.major}.{base.minor + 1}.0")
            return SpecifierSet(f">={base},<{upper}")
        if spec.startswith((">=", "<=", ">", "<", "==")):
            return SpecifierSet(spec)
        return SpecifierSet(f"=={spec}")
    except (InvalidVersion, ValueError):
        return None


def fetch_package_metadata(pkg: str, log: Callable[[str], None]) -> dict:
    stub = Path(__file__).parent / "registry_stubs" / f"{pkg}.json"
    if stub.exists():
        log(f"[npm] stub://{pkg} (demo)")
        return json.loads(stub.read_text())
    log(f"[npm] GET {NPM_REGISTRY}/{pkg}")
    with httpx.Client(timeout=15) as c:
        r = c.get(f"{NPM_REGISTRY}/{pkg}")
        r.raise_for_status()
        return r.json()


def list_versions(meta: dict) -> list[str]:
    versions = list(meta.get("versions", {}).keys())
    def key(v: str):
        try:
            return Version(v)
        except InvalidVersion:
            return Version("0.0.0")
    return sorted(versions, key=key)


def peer_deps_for(meta: dict, version: str) -> dict:
    return (meta.get("versions", {}).get(version, {}) or {}).get("peerDependencies", {}) or {}


# --- conflict detection -------------------------------------------------------

def simulate_install_conflict(
    app_pkg_json: dict, finding: Finding, log: Callable[[str], None]
) -> Optional[ConflictInfo]:
    """Detect whether bumping `finding.package` to `recommended_version` breaks a peer
    declared by another dep. Simulated deterministically from local package.json + registry."""
    target_ver = finding.recommended_version
    for dep_name in app_pkg_json.get("dependencies", {}):
        if dep_name == finding.package:
            continue
        try:
            meta = fetch_package_metadata(dep_name, log)
        except Exception as e:
            log(f"[npm] skip {dep_name}: {e}")
            continue
        dep_version = app_pkg_json["dependencies"][dep_name]
        peers = peer_deps_for(meta, dep_version)
        if finding.package not in peers:
            continue
        peer_range = peers[finding.package]
        log(f"[conflict] {dep_name}@{dep_version} peer requires {finding.package}{peer_range}")
        spec = _npm_semver_to_pep440(peer_range)
        try:
            target_v = Version(target_ver)
        except InvalidVersion:
            continue
        if spec and target_v in spec:
            log(f"[conflict] target {target_ver} satisfies peer — no conflict")
            continue
        # Real conflict. Search for a blocker version that accepts fixed axios.
        compat = None
        for v in reversed(list_versions(meta)):
            new_peer = peer_deps_for(meta, v).get(finding.package)
            if not new_peer:
                continue
            new_spec = _npm_semver_to_pep440(new_peer)
            if new_spec and target_v in new_spec:
                compat = v
                log(f"[resolve] {dep_name}@{v} accepts {finding.package}{new_peer}")
                break
        return ConflictInfo(
            blocker_pkg=dep_name,
            blocker_version=dep_version,
            peer_range=peer_range,
            blocker_versions_available=list_versions(meta),
            compatible_blocker_upgrade=compat,
        )
    return None


# --- Claude reasoning ---------------------------------------------------------

SYSTEM_PROMPT = """You are a dependency-remediation reasoning engine.
Input: a CVE finding + optional peer-conflict info from an npm-style dep graph.
Output: ONE JSON object matching this schema (no prose, no code fences):

{
  "kind": "coordinated_upgrade" | "safe_minor_bump" | "nested_isolation" | "escalate",
  "rationale": "1-3 sentence reasoning",
  "patches": { "<pkg>": "<version>", ... },   // packages to change; empty if escalate
  "risk_notes": "residual risks / follow-ups",
  "requires_human": true|false
}

Strategy priority (pick the highest that applies):
1. safe_minor_bump — if a version of the vuln package inside the peer range but OUTSIDE the vulnerable range exists.
2. coordinated_upgrade — bump both the vuln pkg AND the blocker pkg together (blocker version must accept the new vuln pkg).
3. nested_isolation — allow nested duplicate ONLY if the vulnerable copy is isolated from untrusted input. Note residual risk.
4. escalate — no safe automated fix; set requires_human=true.

Return ONLY the JSON object."""


def ask_claude(finding: Finding, conflict: Optional[ConflictInfo], log: Callable[[str], None]) -> Strategy:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set. Copy .env.example -> .env.")
    model = os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-8")
    client = Anthropic(api_key=api_key)

    user_payload = {
        "finding": finding.__dict__,
        "conflict": conflict.__dict__ if conflict else None,
    }
    log(f"[claude] model={model} — reasoning about strategy…")
    resp = client.messages.create(
        model=model,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(user_payload, indent=2)}],
    )
    text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text").strip()
    # Strip accidental code fences.
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    data = json.loads(text)
    return Strategy(
        kind=data["kind"],
        rationale=data["rationale"],
        patches=data.get("patches", {}) or {},
        risk_notes=data.get("risk_notes", ""),
        requires_human=bool(data.get("requires_human", False)),
    )


# --- patch + git --------------------------------------------------------------

def apply_patch(app_dir: Path, strategy: Strategy) -> Optional[str]:
    pkg_path = app_dir / "package.json"
    pkg = json.loads(pkg_path.read_text())
    for name, ver in strategy.patches.items():
        if name in pkg.get("dependencies", {}):
            pkg["dependencies"][name] = ver
    content = json.dumps(pkg, indent=2) + "\n"
    pkg_path.write_text(content)
    return content


def git_branch_and_commit(repo_dir: Path, finding: Finding, strategy: Strategy) -> str:
    branch = f"fix/{finding.cve.lower()}-{finding.package}"
    _run(["git", "checkout", "-B", branch], cwd=repo_dir)
    _run(["git", "add", "-A"], cwd=repo_dir)
    msg = f"fix({finding.package}): remediate {finding.cve} via {strategy.kind}"
    _run(["git", "commit", "-m", msg], cwd=repo_dir)
    return branch


def _run(cmd: list[str], cwd: Path) -> str:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return r.stdout


def build_pr_body(finding: Finding, conflict: Optional[ConflictInfo], strategy: Strategy) -> str:
    lines = [
        f"## Auto-remediation for {finding.cve}",
        "",
        f"**Package:** `{finding.package}@{finding.current_version}` → **{finding.severity}**",
        f"**Summary:** {finding.summary}",
        "",
        "### Direct-bump attempt",
    ]
    if conflict:
        lines += [
            f"Bumping to `{finding.recommended_version}` conflicts with peer of "
            f"`{conflict.blocker_pkg}@{conflict.blocker_version}` (`{finding.package}{conflict.peer_range}`).",
        ]
        if conflict.compatible_blocker_upgrade:
            lines.append(
                f"`{conflict.blocker_pkg}@{conflict.compatible_blocker_upgrade}` accepts the fixed version."
            )
    else:
        lines.append("No peer conflict detected.")
    lines += [
        "",
        f"### Strategy: `{strategy.kind}`",
        strategy.rationale,
        "",
        "### Patches",
    ]
    if strategy.patches:
        for k, v in strategy.patches.items():
            lines.append(f"- `{k}` → `{v}`")
    else:
        lines.append("_none — escalated for human review_")
    lines += [
        "",
        "### Residual risk / follow-ups",
        strategy.risk_notes or "_none_",
        "",
        "### Validation",
        "- [ ] `npm install` resolves cleanly",
        "- [ ] unit + regression suite pass",
        "- [ ] runtime smoke test against affected code paths",
        "",
        "_Generated by fix-tool + Claude._",
    ]
    return "\n".join(lines)


# --- top-level orchestrator ---------------------------------------------------

def remediate(app_dir: Path, log: Callable[[str], None]) -> RemediationResult:
    report = json.loads((app_dir / "xray-report.json").read_text())
    raw = report["findings"][0]
    finding = Finding(
        cve=raw["cve"],
        package=raw["package"],
        current_version=raw["current_version"],
        vulnerable_range=raw["vulnerable_range"],
        fixed_range=raw["fixed_range"],
        recommended_version=raw["recommended_version"],
        severity=raw["severity"],
        summary=raw["summary"],
    )
    log(f"[xray] {finding.cve} — {finding.package}@{finding.current_version} → {finding.recommended_version}")

    pkg = json.loads((app_dir / "package.json").read_text())
    conflict = simulate_install_conflict(pkg, finding, log)
    if conflict:
        log(f"[conflict] ERESOLVE with {conflict.blocker_pkg}@{conflict.blocker_version}")
    else:
        log("[conflict] none")

    strategy = ask_claude(finding, conflict, log)
    log(f"[claude] strategy={strategy.kind} patches={strategy.patches}")

    patched = None
    branch = None
    if not strategy.requires_human and strategy.patches:
        patched = apply_patch(app_dir, strategy)
        log("[patch] package.json rewritten")

    pr_body = build_pr_body(finding, conflict, strategy)
    return RemediationResult(
        finding=finding,
        conflict=conflict,
        strategy=strategy,
        branch=branch,
        pr_body=pr_body,
        patched_package_json=patched,
    )


def commit_and_branch(app_dir: Path, result: RemediationResult, log: Callable[[str], None]) -> str:
    if result.strategy.requires_human or not result.patched_package_json:
        raise RuntimeError("Nothing to commit — strategy escalated to human.")
    repo = _find_repo_root(app_dir)
    branch = git_branch_and_commit(repo, result.finding, result.strategy)
    pr_path = app_dir / "PR_BODY.md"
    pr_path.write_text(result.pr_body)
    _run(["git", "add", str(pr_path.relative_to(repo))], cwd=repo)
    subprocess.run(["git", "commit", "--amend", "--no-edit"], cwd=repo, capture_output=True)
    result.branch = branch
    log(f"[git] branch={branch} committed")
    return branch


def _find_repo_root(start: Path) -> Path:
    p = start.resolve()
    while p != p.parent:
        if (p / ".git").exists():
            return p
        p = p.parent
    raise RuntimeError("no .git found")
