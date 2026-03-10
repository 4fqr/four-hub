"""Four-Hub · python/wrappers/ffuf_wrapper.py"""
from __future__ import annotations
import json
import re
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit

_RE_LINE = re.compile(r"\[Status:\s*(\d+).*?Words:\s*(\d+).*?\]\s+\*\s+FUZZ:\s+(\S+)")


class FfufWrapper(ToolWrapper):
    name = "ffuf"

    def build_command(self, target: str) -> list[str]:
        return [
            "ffuf",
            "-u", f"{target}/FUZZ",
            "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "-json", "-o", f"/tmp/fh_ffuf_{target.replace('://', '_').replace('/', '_')}.json",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        m = _RE_LINE.search(line)
        if m:
            status, _, path = m.groups()
            sev = "medium" if status in ("200", "201") else "info"
            f = self.finding(
                tool        = "ffuf",
                title       = f"FFUF: {path} [{status}]",
                description = f"FFUF found {target}/{path} returning HTTP {status}.",
                severity    = sev,
                evidence    = line.strip(),
            )
            emit(f)
            yield f

    def parse_output(self, output: str, target: str) -> Iterator[Finding]:
        try:
            data = json.loads(output)
            for r in data.get("results", []):
                url    = r.get("url", "")
                status = str(r.get("status", ""))
                sev    = "medium" if status in ("200", "201") else "info"
                f = self.finding(
                    tool        = "ffuf",
                    title       = f"FFUF: {url} [{status}]",
                    description = f"URL: {url}\nStatus: {status}",
                    severity    = sev,
                    evidence    = json.dumps(r),
                )
                emit(f)
                yield f
        except Exception:
            yield from super().parse_output(output, target)
