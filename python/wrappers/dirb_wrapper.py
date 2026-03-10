"""Four-Hub · python/wrappers/dirb_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_FOUND    = re.compile(r"\+\s+(https?://\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)")
_RE_ENTERING = re.compile(r"ENTERING DIRECTORY:\s+(\S+)", re.I)


class DirbWrapper(ToolWrapper):
    name = "dirb"

    def build_command(self, target: str) -> list[str]:
        return [
            "dirb",
            target,
            "/usr/share/dirb/wordlists/common.txt",
            "-r",
            "-o", "/tmp/fh_dirb_output.txt",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        m = _RE_FOUND.search(line)
        if m:
            url, code, size = m.group(1), m.group(2), m.group(3)
            severity = "info"
            if int(code) in (200, 301, 302):
                lurl = url.lower()
                if any(k in lurl for k in ("admin", "login", "config", "backup", ".bak", ".sql", ".env")):
                    severity = "high"
                elif int(code) == 200:
                    severity = "medium"
            f = self.finding(
                tool        = "dirb",
                title       = f"Directory found: {url}",
                description = f"URL: {url}\nHTTP {code}, {size} bytes",
                severity    = severity,
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        m_dir = _RE_ENTERING.search(line)
        if m_dir:
            directory = m_dir.group(1)
            f = self.finding(
                tool        = "dirb",
                title       = f"Entering directory: {directory}",
                description = f"dirb is recursing into {directory}",
                severity    = "info",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
