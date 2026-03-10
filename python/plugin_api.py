"""
Four-Hub Python Wrapper API
===========================
Base classes and shared utilities for all tool wrappers.
Each wrapper must implement the `ToolWrapper` interface and return
a list of `Finding` dicts normalised to the schema used by the Rust core.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Iterator, List, Optional
import uuid


# ── Finding schema ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """Normalised finding – mirrors db::Finding on the Rust side."""
    id:          str               = field(default_factory=lambda: str(uuid.uuid4()))
    tool:        str               = ""
    title:       str               = ""
    description: str               = ""
    severity:    str               = "info"   # critical|high|medium|low|info
    evidence:    Optional[str]     = None
    host_id:     Optional[str]     = None
    port_id:     Optional[str]     = None
    created_at:  str               = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


# ── Base wrapper ──────────────────────────────────────────────────────────────

class ToolWrapper(ABC):
    """
    Base class for Four-Hub tool wrappers.

    The Rust executor calls `run(target)` which yields `Finding` objects
    (as dicts) line by line via stdout, or can be called with
    `parse_output(raw_output)` for post-processing.
    """

    #: Tool name as registered in tools.toml
    name: str = "unknown"

    # ── override in subclasses ────────────────────────────────────────────────

    @abstractmethod
    def build_command(self, target: str) -> List[str]:
        """Return the full argv list for this tool."""
        ...

    def parse_line(self, line: str, target: str) -> Iterator[Finding]:
        """
        Parse a single stdout/stderr line and yield zero or more findings.
        Subclasses override this for real-time streaming parse.
        """
        return
        yield  # make this a generator

    def parse_output(self, output: str, target: str) -> Iterator[Finding]:
        """
        Parse the full tool output (e.g. a JSON blob) and yield findings.
        Default: call parse_line for each line.
        """
        for line in output.splitlines():
            yield from self.parse_line(line, target)

    # ── helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def finding(
        tool:        str,
        title:       str,
        description: str,
        severity:    str               = "info",
        evidence:    Optional[str]     = None,
    ) -> Finding:
        return Finding(
            tool        = tool,
            title       = title,
            description = description,
            severity    = severity,
            evidence    = evidence,
        )

    @staticmethod
    def is_installed(binary: str) -> bool:
        import shutil
        return shutil.which(binary) is not None


# ── Utility helpers ────────────────────────────────────────────────────────────

def emit(finding: Finding) -> None:
    """Print a finding as a JSON line to stdout for the Rust executor to pick up."""
    tag = "FOUR_HUB_FINDING:"
    print(f"{tag}{finding.to_json()}", flush=True)


def severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0: return "critical"
    if cvss >= 7.0: return "high"
    if cvss >= 4.0: return "medium"
    if cvss >= 0.1: return "low"
    return "info"
