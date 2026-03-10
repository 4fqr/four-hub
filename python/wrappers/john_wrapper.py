"""Four-Hub · python/wrappers/john_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_CRACK = re.compile(r"^(\S.*?)\s+\((\S+)\)")
_RE_DONE  = re.compile(r"session completed", re.I)


class JohnWrapper(ToolWrapper):
    name = "john"

    def build_command(self, target: str) -> list[str]:
        return [
            "john",
            "--wordlist=/usr/share/wordlists/rockyou.txt",
            target,
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        m = _RE_CRACK.match(line.strip())
        if m:
            password, username = m.groups()
            f = self.finding(
                tool        = "john",
                title       = f"Hash cracked: {username}",
                description = f"Username: {username}\nPassword: {password}",
                severity    = "critical",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        if _RE_DONE.search(line):
            f = self.finding(
                tool        = "john",
                title       = "John the Ripper session completed",
                description = "All hashes processed — session finished.",
                severity    = "info",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
