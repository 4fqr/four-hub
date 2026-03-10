"""Four-Hub · python/wrappers/eyewitness_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_SCREENSHOT = re.compile(r"Attempting to screenshot:\s+(\S+)", re.I)
_RE_INTERESTING = re.compile(r"(login|admin|dashboard|vpn|webmail|cpanel)", re.I)
_RE_TIMEOUT     = re.compile(r"timed out", re.I)


class EyewitnessWrapper(ToolWrapper):
    name = "eyewitness"

    def build_command(self, target: str) -> list[str]:
        return [
            "eyewitness",
            "--single",
            target,
            "--timeout", "15",
            "--no-prompt",
            "-d", "/tmp/fh_eyewitness",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        m = _RE_SCREENSHOT.search(line)
        if m:
            url = m.group(1)
            severity = "info"
            if _RE_INTERESTING.search(url):
                severity = "high"
            f = self.finding(
                tool        = "eyewitness",
                title       = f"Screenshot: {url}",
                description = f"EyeWitness captured screenshot of {url}",
                severity    = severity,
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        if _RE_TIMEOUT.search(line):
            f = self.finding(
                tool        = "eyewitness",
                title       = "EyeWitness timeout",
                description = f"Connection timed out: {line.strip()}",
                severity    = "info",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
