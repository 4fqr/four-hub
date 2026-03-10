"""Four-Hub · python/wrappers/smbclient_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_SHARE    = re.compile(r"\s+(\S+)\s+(?:Disk|IPC|Printer)")
_RE_ANON     = re.compile(r"anonymous login|guest login", re.I)
_RE_FILE     = re.compile(r"^\s+(\d+)\s+\w{3}\s+\d+\s+\d{4}\s+(.+)\s*$")
_RE_DENIED   = re.compile(r"NT_STATUS_ACCESS_DENIED", re.I)


class SmbclientWrapper(ToolWrapper):
    name = "smbclient"

    def build_command(self, target: str) -> list[str]:
        return [
            "smbclient",
            "-L", target,
            "-N",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        if _RE_ANON.search(line):
            f = self.finding(
                tool        = "smbclient",
                title       = f"Anonymous SMB login on {target}",
                description = f"SMB server {target} allows anonymous / guest login.",
                severity    = "high",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        m_share = _RE_SHARE.search(line)
        if m_share:
            share = m_share.group(1)
            f = self.finding(
                tool        = "smbclient",
                title       = f"SMB share: {share}",
                description = f"Share {share} advertised on {target}.",
                severity    = "medium",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        m_file = _RE_FILE.match(line)
        if m_file:
            size, name = m_file.groups()
            severity = "info"
            if any(ext in name.lower() for ext in (".bak", ".sql", ".cfg", ".conf", ".env", ".key", ".pem")):
                severity = "high"
            f = self.finding(
                tool        = "smbclient",
                title       = f"File on share: {name.strip()}",
                description = f"File {name.strip()} ({size} bytes) on {target}.",
                severity    = severity,
                evidence    = line.strip(),
            )
            emit(f)
            yield f
