"""Four-Hub · python/wrappers/sqlmap_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_VULN   = re.compile(r"Parameter '(\w+)' is vulnerable")
_RE_DB     = re.compile(r"available databases \[(\d+)\]")
_RE_TABLE  = re.compile(r"Database:\s+(\S+)")
_RE_DUMP   = re.compile(r"\[INFO\]\s+fetching\s+(.*)")


class SqlmapWrapper(ToolWrapper):
    name = "sqlmap"

    def build_command(self, target: str) -> list[str]:
        return [
            "sqlmap", "-u", target,
            "--batch", "--output-dir=/tmp/fh_sqlmap/",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        m = _RE_VULN.search(line)
        if m:
            param = m.group(1)
            f = self.finding(
                tool        = "sqlmap",
                title       = f"SQL Injection in parameter '{param}'",
                description = f"SQLmap confirmed SQL injection in '{param}' at {target}.",
                severity    = "critical",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        m = _RE_DB.search(line)
        if m:
            f = self.finding(
                tool        = "sqlmap",
                title       = f"{m.group(1)} databases enumerated",
                description = f"SQLmap enumerated databases from {target}.",
                severity    = "high",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
