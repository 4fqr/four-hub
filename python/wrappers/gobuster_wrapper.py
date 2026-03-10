"""Four-Hub · python/wrappers/gobuster_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_DIR   = re.compile(r"^/(\S+)\s+\(Status:\s*(\d+)\)")
_RE_DIR2  = re.compile(r"Found:\s+(/\S+)\s+\[(\d+)")


class GobusterWrapper(ToolWrapper):
    name = "gobuster"

    def build_command(self, target: str) -> list[str]:
        return [
            "gobuster", "dir",
            "-u", target,
            "-w", "/usr/share/wordlists/dirb/common.txt",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        for pat in (_RE_DIR, _RE_DIR2):
            m = pat.search(line.strip())
            if m:
                path, status = m.group(1), m.group(2)
                sev = "medium" if status in ("200", "201", "301", "302") else "info"
                f = self.finding(
                    tool        = "gobuster",
                    title       = f"/{path} ({status})",
                    description = f"Gobuster: {target}/{path} → HTTP {status}",
                    severity    = sev,
                    evidence    = line.strip(),
                )
                emit(f)
                yield f
                return
