"""Four-Hub · python/wrappers/nuclei_wrapper.py"""
from __future__ import annotations
import json
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit, severity_from_cvss

_SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "info", "unknown": "info"}


class NucleiWrapper(ToolWrapper):
    name = "nuclei"

    def build_command(self, target: str) -> list[str]:
        return [
            "nuclei", "-u", target,
            "-json", "-o", f"/tmp/fh_nuclei_{target.replace('://', '_').replace('/', '_')}.json",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        line = line.strip()
        if not line.startswith("{"):
            return
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return

        tmpl  = rec.get("template-id", "unknown")
        info  = rec.get("info", {})
        sev   = _SEV_MAP.get(info.get("severity", "info").lower(), "info")
        title = info.get("name", tmpl)
        matched = rec.get("matched-at", target)
        desc  = info.get("description", "")

        f = self.finding(
            tool        = "nuclei",
            title       = f"[{sev.upper()}] {title} on {matched}",
            description = f"Template: {tmpl}\nMatched: {matched}\n{desc}",
            severity    = sev,
            evidence    = line,
        )
        emit(f)
        yield f
