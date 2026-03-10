"""Four-Hub · python/wrappers/hydra_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_CRED = re.compile(r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)")


class HydraWrapper(ToolWrapper):
    name = "hydra"

    def build_command(self, target: str) -> list[str]:
        return [
            "hydra",
            "-L", "/usr/share/wordlists/metasploit/unix_users.txt",
            "-P", "/usr/share/wordlists/rockyou.txt",
            target, "ssh",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        m = _RE_CRED.search(line)
        if m:
            _, service, host, login, password = m.groups()
            f = self.finding(
                tool        = "hydra",
                title       = f"Valid credential on {host} [{service}]: {login}",
                description = (
                    f"Hydra found valid credentials:\n"
                    f"Host:     {host}\n"
                    f"Service:  {service}\n"
                    f"Login:    {login}\n"
                    f"Password: {password}"
                ),
                severity    = "critical",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
