"""Four-Hub · python/wrappers/aircrack_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_KEY   = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")
_RE_SSID  = re.compile(r"SSID:\s+(\S+)")


class AircrackWrapper(ToolWrapper):
    name = "aircrack-ng"

    def build_command(self, target: str) -> list[str]:
        return ["aircrack-ng", "-w", "/usr/share/wordlists/rockyou.txt", target]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        m = _RE_KEY.search(line)
        if m:
            key = m.group(1)
            f = self.finding(
                tool        = "aircrack-ng",
                title       = f"WPA/WEP key found: {key}",
                description = f"Aircrack-ng cracked the wireless passphrase.\nKey: {key}\nCapture: {target}",
                severity    = "critical",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
