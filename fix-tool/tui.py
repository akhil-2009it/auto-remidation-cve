"""Textual TUI: one-key remediation. F = fix, Q = quit."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Log, Markdown, Static

from remediator import (
    RemediationResult,
    commit_and_branch,
    remediate,
)


APP_DIR = Path(__file__).resolve().parent.parent / "vulnerable-app"


class RemediateApp(App):
    CSS = """
    Screen { layout: vertical; }
    #top { height: 40%; }
    #findings { width: 45%; border: solid $accent; }
    #details { width: 55%; border: solid $accent; padding: 0 1; }
    #log-panel { height: 30%; border: solid $secondary; }
    #pr-panel { height: 30%; border: solid $success; padding: 0 1; }
    .status-ok { color: $success; }
    .status-warn { color: $warning; }
    .status-err { color: $error; }
    """
    BINDINGS = [
        ("f", "fix", "One-click Fix"),
        ("c", "commit", "Commit + Branch"),
        ("r", "reload", "Reload findings"),
        ("q", "quit", "Quit"),
    ]

    result: reactive[Optional[RemediationResult]] = reactive(None)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="top"):
            yield DataTable(id="findings", cursor_type="row")
            yield VerticalScroll(Static("Select a finding.\n\nPress **F** to fix.", id="details"))
        yield Log(id="log-panel", highlight=True)
        yield VerticalScroll(Markdown("_PR preview will appear here after fix._", id="pr-panel"))
        yield Footer()

    def on_mount(self) -> None:
        self.title = "vuln-demo · auto-remediation"
        self.sub_title = str(APP_DIR)
        self._load_findings()

    # -- findings table --

    def _load_findings(self) -> None:
        table: DataTable = self.query_one("#findings", DataTable)
        table.clear(columns=True)
        table.add_columns("CVE", "Package", "Version", "Severity", "Fixed In")
        try:
            report = json.loads((APP_DIR / "xray-report.json").read_text())
        except FileNotFoundError:
            self._log("[error] xray-report.json missing")
            return
        for f in report["findings"]:
            table.add_row(
                f["cve"], f["package"], f["current_version"],
                f["severity"], f["recommended_version"],
            )
        table.focus()
        self._render_details(report["findings"][0] if report["findings"] else None)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        report = json.loads((APP_DIR / "xray-report.json").read_text())
        idx = event.cursor_row
        if 0 <= idx < len(report["findings"]):
            self._render_details(report["findings"][idx])

    def _render_details(self, f: Optional[dict]) -> None:
        panel: Static = self.query_one("#details", Static)
        if not f:
            panel.update("No findings.")
            return
        panel.update(
            f"[b]{f['cve']}[/b]  [{f['severity'].lower()}]{f['severity']}[/]\n"
            f"[b]Package:[/b] {f['package']}@{f['current_version']}\n"
            f"[b]Fixed range:[/b] {f['fixed_range']}\n"
            f"[b]Recommended:[/b] {f['recommended_version']}\n\n"
            f"{f['summary']}\n\n"
            f"[dim]Press [b]F[/b] to run remediation.[/dim]"
        )

    # -- logging --

    def _log(self, msg: str) -> None:
        log: Log = self.query_one("#log-panel", Log)
        log.write_line(msg)

    # -- actions --

    async def action_fix(self) -> None:
        self._log("── running remediation ──")
        self.result = None
        try:
            result = await asyncio.to_thread(remediate, APP_DIR, self._log)
        except Exception as e:
            self._log(f"[error] {e}")
            return
        self.result = result
        self._log(f"[done] strategy={result.strategy.kind}")
        self.query_one("#pr-panel", VerticalScroll).query_one(Markdown).update(result.pr_body)
        if result.strategy.requires_human:
            self._log("[warn] escalation — no auto-fix applied. Review PR body.")
        else:
            self._log("[ok] patch written. Press [C] to commit + branch.")

    async def action_commit(self) -> None:
        if not self.result:
            self._log("[warn] run fix first (F).")
            return
        if self.result.strategy.requires_human:
            self._log("[warn] escalated — nothing to commit.")
            return
        try:
            branch = await asyncio.to_thread(commit_and_branch, APP_DIR, self.result, self._log)
        except Exception as e:
            self._log(f"[error] {e}")
            return
        self._log(f"[ok] branch {branch} created + committed. Ready for PR.")

    def action_reload(self) -> None:
        self._load_findings()
        self._log("[info] findings reloaded")


def main() -> None:
    load_dotenv(Path(__file__).parent / ".env")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY not set. cp .env.example .env and fill in.")
        raise SystemExit(2)
    RemediateApp().run()


if __name__ == "__main__":
    main()
