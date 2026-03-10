"""Four-Hub · python/wrappers/wifite_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_CRACKED = re.compile(r"\[\+\]\s+(\S+)\s+\((\S+)\)\s+PASSWORD:\s+(.+)")
_RE_HANDSHAKE = re.compile(r"handshake.*?captured", re.I)


class WifiteWrapper(ToolWrapper):
    name = "wifite"
    is_interactive = True

    def build_command(self, target: str) -> list[str]:
        return ["wifite", "--kill", "--dict", "/usr/share/wordlists/rockyou.txt"]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        m = _RE_CRACKED.search(line)
        if m:
            bssid, essid, pwd = m.groups()
            f = self.finding(
                tool        = "wifite",
                title       = f"Wi-Fi cracked: {essid}",
                description = f"BSSID: {bssid}\nESSID: {essid}\nPassword: {pwd}",
                severity    = "critical",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        if _RE_HANDSHAKE.search(line):
            f = self.finding(
                tool        = "wifite",
                title       = "WPA handshake captured",
                description = f"Wifite captured a WPA handshake.\n{line.strip()}",
                severity    = "high",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
