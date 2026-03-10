"""
Four-Hub · python/wrappers/nikto_wrapper.py
Parses Nikto JSON output and real-time line output into findings.
"""

from __future__ import annotations
import json
import re
from typing import Iterator

from ..plugin_api import Finding, ToolWrapper, emit

_RE_PLUS = re.compile(r"^\+\s+(.*)")
_RE_CVE  = re.compile(r"(CVE-[\d-]+)")
_RE_OSVDB = re.compile(r"OSVDB-(\d+)")


class NiktoWrapper(ToolWrapper):
    name = "nikto"

    def build_command(self, target: str) -> list[str]:
        return [
            "nikto", "-h", target,
            "-Format", "json",
            "-output", f"/tmp/fh_nikto_{target.replace('/', '_')}.json",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        m = _RE_PLUS.match(line.strip())
        if not m:
            return

        msg = m.group(1).strip()
        if not msg or msg.startswith("-") or len(msg) < 10:
            return

        # Determine severity.
        cve_match   = _RE_CVE.search(msg)
        osvdb_match = _RE_OSVDB.search(msg)
        sev = "info"
        if cve_match or any(kw in msg.lower() for kw in ("inject", "bypass", "rce", "exec")):
            sev = "high"
        elif osvdb_match or any(kw in msg.lower() for kw in ("disclos", "version", "outdated")):
            sev = "medium"

        finding = self.finding(
            tool        = "nikto",
            title       = msg[:80],
            description = f"Nikto finding on {target}:\n{msg}",
            severity    = sev,
            evidence    = line.strip(),
        )
        emit(finding)
        yield finding

    def parse_output(self, output: str, target: str) -> Iterator[Finding]:
        """Try JSON parse; fall back to line-by-line."""
        try:
            data     = json.loads(output)
            vulns    = data.get("vulnerabilities", [])
            for v in vulns:
                msg = v.get("msg", "")
                sev = "medium" if v.get("OSVDBID") else "info"
                f = self.finding(
                    tool        = "nikto",
                    title       = msg[:80],
                    description = f"Host: {target}\n{msg}",
                    severity    = sev,
                    evidence    = json.dumps(v),
                )
                emit(f)
                yield f
        except (json.JSONDecodeError, KeyError):
            yield from super().parse_output(output, target)
