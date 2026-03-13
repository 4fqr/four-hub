"""Four-Hub · python/wrappers/wpscan_wrapper.py"""
from __future__ import annotations
import json
from typing import Iterator
from ..plugin_api import Finding, ToolWrapper, emit


class WpscanWrapper(ToolWrapper):
    name = "wpscan"

    def build_command(self, target: str) -> list[str]:
        return [
            "wpscan",
            "--url", target,
            "--format", "json",
            "--output", f"/tmp/fh_wpscan_{target.replace('://', '_').replace('/', '_')}.json",
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        if "[!]" in line:
            msg = line.strip().lstrip("[!]").strip()
            if msg:
                sev = "high" if any(kw in msg.lower() for kw in ("rce", "sqli", "xss", "exploit")) else "medium"
                f = self.finding(
                    tool="wpscan", title=msg[:80],
                    description=f"WPScan: {msg}", severity=sev, evidence=line.strip(),
                )
                emit(f)
                yield f

    def parse_output(self, output: str, target: str) -> Iterator[Finding]:
        try:
            data = json.loads(output)

            for _slug, pdata in data.get("plugins", {}).items():
                for vuln in pdata.get("vulnerabilities", []):
                    title = vuln.get("title", "WP plugin vulnerability")
                    cvss  = vuln.get("cvss", {}).get("score", 0.0)
                    f = self.finding(
                        tool="wpscan", title=title[:80],
                        description=f"Plugin: {_slug}\n{title}\nTarget: {target}",
                        severity="high" if cvss >= 7 else "medium",
                        evidence=json.dumps(vuln),
                    )
                    emit(f)
                    yield f

            for _slug, tdata in data.get("themes", {}).items():
                for vuln in tdata.get("vulnerabilities", []):
                    title = vuln.get("title", "WP theme vulnerability")
                    f = self.finding(
                        tool="wpscan", title=title[:80],
                        description=f"Theme: {_slug}\n{title}\nTarget: {target}",
                        severity="medium", evidence=json.dumps(vuln),
                    )
                    emit(f)
                    yield f
        except Exception:
            yield from super().parse_output(output, target)
