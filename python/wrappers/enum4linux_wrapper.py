"""Four-Hub · python/wrappers/enum4linux_wrapper.py"""
from __future__ import annotations
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_SHARE    = re.compile(r"//[\d.]+/(\S+)\s+Disk", re.I)
_RE_USER     = re.compile(r"user:\s*\[(\S+)\]", re.I)
_RE_GROUP    = re.compile(r"group:\s*\[(\S+)\]", re.I)
_RE_PASSWORD = re.compile(r"(minimum password length|password complexity|lockout threshold).*?(\d+)", re.I)


class Enum4linuxWrapper(ToolWrapper):
    name = "enum4linux"

    def build_command(self, target: str) -> list[str]:
        return ["enum4linux", "-a", target]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        m_share = _RE_SHARE.search(line)
        if m_share:
            share = m_share.group(1)
            f = self.finding(
                tool        = "enum4linux",
                title       = f"SMB share: {share}",
                description = f"Share {share} discovered on {target}.",
                severity    = "medium",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        m_user = _RE_USER.search(line)
        if m_user:
            user = m_user.group(1)
            f = self.finding(
                tool        = "enum4linux",
                title       = f"User enumerated: {user}",
                description = f"SMB user {user} discovered on {target}.",
                severity    = "medium",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        m_grp = _RE_GROUP.search(line)
        if m_grp:
            group = m_grp.group(1)
            f = self.finding(
                tool        = "enum4linux",
                title       = f"Group enumerated: {group}",
                description = f"SMB group {group} discovered on {target}.",
                severity    = "info",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
            return

        m_pwd = _RE_PASSWORD.search(line)
        if m_pwd:
            policy, value = m_pwd.group(1), m_pwd.group(2)
            f = self.finding(
                tool        = "enum4linux",
                title       = f"Password policy: {policy}={value}",
                description = f"Password policy setting on {target}: {policy} = {value}",
                severity    = "medium",
                evidence    = line.strip(),
            )
            emit(f)
            yield f
