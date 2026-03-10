"""Four-Hub · python/wrappers/hashcat_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_CRACKED = re.compile(r"^([a-fA-F0-9*$]{20,}):(.+)$")
_RE_STATUS  = re.compile(r"Status\.\.\.\.\.\.\.\.\.\.\.\.(Cracked|Exhausted|Running|Aborted)", re.I)


class HashcatWrapper(ToolWrapper):
    name = "hashcat"

    def build_command(self, target: str) -> list[str]:
        return [
            "hashcat",
            "-a", "0",
            target,
            "/usr/share/wordlists/rockyou.txt",
            "--force",
            "--quiet",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        m_status = _RE_STATUS.match(line.strip())
        if m_status:
            status = m_status.group(1).lower()
            if status == "cracked":
                f = self.finding(
                    tool        = "hashcat",
                    title       = "Hashcat: all hashes cracked",
                    description = "Hashcat finished with status: Cracked.",
                    severity    = "critical",
                    evidence    = line.strip(),
                )
                emit(f)
                yield f
            return

        m = _RE_CRACKED.match(line.strip())
        if m:
            hash_val, password = m.groups()
            f = self.finding(
                tool        = "hashcat",
                title       = f"Hash cracked: {hash_val[:16]}…",
                description = f"Hash : {hash_val}\nPlain: {password}",
                severity    = "critical",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
