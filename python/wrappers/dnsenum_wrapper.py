"""Four-Hub · python/wrappers/dnsenum_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_SUBDOMAIN = re.compile(
    r"^(\S+\.\S+\.\S+)\s+\d+\s+IN\s+A\s+([\d.]+)"
)
_RE_ZONE_XFER = re.compile(r"zone transfer", re.I)
_RE_MX        = re.compile(r"MX\s+\d+\s+(\S+)")


class DnsenumWrapper(ToolWrapper):
    name = "dnsenum"

    def build_command(self, target: str) -> list[str]:
        return [
            "dnsenum",
            "--noreverse",
            "--dnsserver", "8.8.8.8",
            target,
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        if _RE_ZONE_XFER.search(line):
            f = self.finding(
                tool        = "dnsenum",
                title       = "DNS zone transfer possible",
                description = f"Zone transfer attempt on {target}.\n{line.strip()}",
                severity    = "high",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        m = _RE_SUBDOMAIN.match(line.strip())
        if m:
            sub, ip = m.groups()
            f = self.finding(
                tool        = "dnsenum",
                title       = f"Subdomain: {sub}",
                description = f"Subdomain {sub} resolves to {ip}",
                severity    = "info",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        m_mx = _RE_MX.search(line)
        if m_mx:
            mx = m_mx.group(1)
            f = self.finding(
                tool        = "dnsenum",
                title       = f"MX record: {mx}",
                description = f"Mail exchanger discovered: {mx}",
                severity    = "info",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
