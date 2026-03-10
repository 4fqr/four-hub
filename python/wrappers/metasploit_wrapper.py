"""Four-Hub · python/wrappers/metasploit_wrapper.py
Thin wrapper that starts msfconsole (interactive).
Finding parsing is done via msfdb JSON export post-launch.
"""
from __future__ import annotations
import json
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_SESSION = re.compile(r"Meterpreter session (\d+) opened.*?->.*?\((\S+)\)")
_RE_MODULE  = re.compile(r"\[\+\]\s+(.*)")


class MetasploitWrapper(ToolWrapper):
    name    = "metasploit"
    is_interactive = True

    def build_command(self, target: str) -> list[str]:
        return ["msfconsole", "-q"]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        m = _RE_SESSION.search(line)
        if m:
            sess_id, rhost = m.groups()
            f = self.finding(
                tool        = "metasploit",
                title       = f"Meterpreter session {sess_id} opened on {rhost}",
                description = f"Metasploit opened Meterpreter session {sess_id} to {rhost}.",
                severity    = "critical",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        m = _RE_MODULE.match(line.strip())
        if m and len(m.group(1)) > 5:
            f = self.finding(
                tool        = "metasploit",
                title       = m.group(1)[:80],
                description = m.group(1),
                severity    = "high",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
