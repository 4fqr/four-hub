"""Four-Hub · python/wrappers/crackmapexec_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_OK      = re.compile(r"\[\+\]\s+(\S+)\s+(\S+):(\S+)(?:\s+(.+))?")
_RE_PWNED   = re.compile(r"Pwn3d!", re.I)
_RE_SHARE   = re.compile(r"SHARE\s+(\S+)\s+READ|WRITE", re.I)
_RE_GUEST   = re.compile(r"STATUS_LOGON_FAILURE|STATUS_ACCESS_DENIED", re.I)


class CrackmapexecWrapper(ToolWrapper):
    name = "crackmapexec"

    def build_command(self, target: str) -> list[str]:
        return [
            "crackmapexec",
            "smb",
            target,
            "-u", "Administrator",
            "-p", "/usr/share/wordlists/rockyou.txt",
            "--continue-on-success",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        pwned = _RE_PWNED.search(line)
        m = _RE_OK.search(line)
        if m and pwned:
            host, user, pwd, extra = m.group(1), m.group(2), m.group(3), m.group(4) or ""
            f = self.finding(
                tool        = "crackmapexec",
                title       = f"Admin credentials valid on {host}",
                description = (
                    f"CrackMapExec confirmed admin-level access.\n"
                    f"Host: {host}\nUser: {user}\nPassword: {pwd}\n{extra}"
                ),
                severity    = "critical",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        if m:
            host, user, pwd, extra = m.group(1), m.group(2), m.group(3), m.group(4) or ""
            f = self.finding(
                tool        = "crackmapexec",
                title       = f"Valid SMB credential on {host}",
                description = (
                    f"Host: {host}\nUser: {user}\nPassword: {pwd}\n{extra}"
                ),
                severity    = "high",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        m_share = _RE_SHARE.search(line)
        if m_share:
            f = self.finding(
                tool        = "crackmapexec",
                title       = f"SMB share accessible: {m_share.group(1)}",
                description = line.strip(),
                severity    = "medium",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
