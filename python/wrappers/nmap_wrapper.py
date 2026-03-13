"""
Four-Hub · python/wrappers/nmap_wrapper.py
Parses grepable Nmap output and XML reports into normalised findings.
"""

from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from typing import Iterator

from ..plugin_api import Finding, ToolWrapper, emit



_RE_PORT    = re.compile(r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.*))?$")
_RE_SCRIPT  = re.compile(r"\|\s+([\w-]+):\s+(.*)")
_RE_OS      = re.compile(r"OS details:\s+(.*)")
_RE_HOST    = re.compile(r"Nmap scan report for (\S+)")


class NmapWrapper(ToolWrapper):
    name = "nmap"

    def build_command(self, target: str) -> list[str]:
        return [
            "nmap", "-sV", "-sC",
            "-oX", f"/tmp/fh_nmap_{target}.xml",
            target,
        ]

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        line = line.strip()


        m = _RE_PORT.match(line)
        if m:
            port, proto, state, service, version = m.groups()
            if state == "open":
                finding = self.finding(
                    tool        = "nmap",
                    title       = f"Open port {port}/{proto} ({service})",
                    description = (
                        f"Host: {target}\n"
                        f"Port: {port}/{proto}\n"
                        f"State: {state}\n"
                        f"Service: {service}\n"
                        f"Version: {version or 'unknown'}"
                    ),
                    severity = "info",
                    evidence = line,
                )
                emit(finding)
                yield finding
            return


        m = _RE_OS.match(line)
        if m:
            finding = self.finding(
                tool        = "nmap",
                title       = f"OS detected: {m.group(1)}",
                description = f"Nmap identified the OS of {target} as: {m.group(1)}",
                severity    = "info",
                evidence    = line,
            )
            emit(finding)
            yield finding

    def parse_xml(self, xml_path: str) -> Iterator[Finding]:
        """Parse a full Nmap XML report after the scan finishes."""
        try:
            tree = ET.parse(xml_path)
        except Exception:
            return

        for host_el in tree.findall("host"):
            addr_el = host_el.find("address")
            addr    = addr_el.get("addr", "?") if addr_el is not None else "?"

            for port_el in host_el.findall(".//port"):
                state_el  = port_el.find("state")
                service_el = port_el.find("service")
                if state_el is None or state_el.get("state") != "open":
                    continue

                portid  = port_el.get("portid", "?")
                proto   = port_el.get("protocol", "tcp")
                service = service_el.get("name", "unknown") if service_el is not None else "unknown"
                version = (
                    f"{service_el.get('product','')} {service_el.get('version','')}".strip()
                    if service_el is not None else ""
                )


                for script_el in port_el.findall("script"):
                    sid    = script_el.get("id", "")
                    output = script_el.get("output", "")
                    sev    = "medium" if any(k in sid for k in ("vuln", "exploit")) else "info"
                    finding = self.finding(
                        tool        = "nmap",
                        title       = f"Script {sid} on {addr}:{portid}",
                        description = f"Host: {addr}\nPort: {portid}/{proto}\nScript: {sid}\n\n{output}",
                        severity    = sev,
                        evidence    = output[:2000],
                    )
                    emit(finding)
                    yield finding
