"""
Four-Hub Example Plugin
========================
Drop this file (or any .py) into your plugins_dir
(default: ~/.local/share/four-hub/plugins/).

Two hooks are recognised:

  on_new_finding(finding: dict)              — fired for every new Finding
  on_tool_finished(job_id: str, code: int)   — fired when a tool process exits

Both are optional; implement only what you need.

Finding dict keys
-----------------
  id          str   — UUID v4
  tool        str   — tool name (e.g. "nmap")
  title       str   — one-line description
  description str   — full detail
  severity    str   — "critical" | "high" | "medium" | "low" | "info"
  evidence    str   — raw parser evidence line
  timestamp   str   — RFC-3339 string
  host        str   — target host (may be empty)
"""

from __future__ import annotations
import json
import pathlib
import datetime


_OUTPUT = pathlib.Path("/tmp/four_hub_plugin_demo.jsonl")


def on_new_finding(finding: dict) -> None:
    """Append each finding as a JSON line to a temp file."""
    entry = {
        **finding,
        "plugin_ts": datetime.datetime.utcnow().isoformat() + "Z",
    }
    with _OUTPUT.open("a") as fh:
        fh.write(json.dumps(entry) + "\n")



    sev = finding.get("severity", "info").upper()
    print(f"[PLUGIN] [{sev}] {finding.get('title', '?')}")


def on_tool_finished(job_id: str, exit_code: int) -> None:
    """Log tool completion events."""
    status = "OK" if exit_code == 0 else f"exit={exit_code}"
    print(f"[PLUGIN] Tool job {job_id} finished — {status}")
