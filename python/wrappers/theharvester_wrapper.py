"""Four-Hub · python/wrappers/theharvester_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_EMAIL  = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_RE_IP     = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_RE_VHOST  = re.compile(r"^\s*-\s+(\S+\.\S+)\s*$")


class TheHarvesterWrapper(ToolWrapper):
    name = "theharvester"

    def build_command(self, target: str) -> list[str]:
        return [
            "theHarvester",
            "-d", target,
            "-b", "all",
            "-l", "500",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        for email in _RE_EMAIL.findall(line):
            f = self.finding(
                tool        = "theharvester",
                title       = f"Email harvested: {email}",
                description = f"E-mail address discovered via OSINT: {email}",
                severity    = "medium",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        m_vhost = _RE_VHOST.match(line)
        if m_vhost:
            host = m_vhost.group(1)
            f = self.finding(
                tool        = "theharvester",
                title       = f"Virtual host: {host}",
                description = f"Virtual / sub-domain discovered: {host}",
                severity    = "info",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        ips = _RE_IP.findall(line.strip())
        if ips and line.strip().startswith(tuple("0123456789")):
            for ip in ips:
                f = self.finding(
                    tool        = "theharvester",
                    title       = f"IP discovered: {ip}",
                    description = f"IP address harvested via OSINT: {ip}",
                    severity    = "info",
                    evidence    = line.strip(),
                )
                emit(f)
                yield f
