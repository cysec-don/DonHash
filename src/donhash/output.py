# DonHash — Advanced Hash Detector & Cracker
# Copyright (c) 2026 CySec Don (cysecdon@gmail.com)
#
# Licensed under the DonHash Attribution License v1.0 (DH-AL).
# See LICENSE file for full terms.
#
# Attribution requirement: All copies, forks, updates, modifications, or
# commercial applications of this software MUST retain the following
# attribution in a prominent location:
#
#     "This software is based on DonHash by CySec Don (cysecdon@gmail.com).
#      Original source: https://github.com/cysec-don/DonHash"
#
# For the full terms of the attribution requirement, see Sections 1-3 of
# the LICENSE file.

"""Output writers for crack results — txt, json, csv, html (XSS-safe), xml, md."""

from __future__ import annotations

import csv
import html
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime

from donhash.cracker import CrackResult

SUPPORTED_FORMATS = ["txt", "json", "csv", "html", "xml", "md"]


def detect_output_format(output_path: str, explicit_format: str | None = None) -> str:
    """Detect output format from file extension or use explicit format."""
    if explicit_format:
        return explicit_format.lower()
    ext = os.path.splitext(output_path)[1].lstrip(".").lower()
    if ext in SUPPORTED_FORMATS:
        return ext
    return "txt"


def write_output(results: list[CrackResult], output_path: str, fmt: str = "txt") -> None:
    """Write crack results to a file in the specified format."""
    if fmt == "json":
        _write_json(results, output_path)
    elif fmt == "csv":
        _write_csv(results, output_path)
    elif fmt == "html":
        _write_html(results, output_path)
    elif fmt == "xml":
        _write_xml(results, output_path)
    elif fmt == "md":
        _write_markdown(results, output_path)
    else:
        _write_txt(results, output_path)


def _result_to_dict(r: CrackResult) -> dict:
    return r.to_dict()


def _write_txt(results: list[CrackResult], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("DonHash v2.0 — Cracking Results\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        for r in results:
            d = _result_to_dict(r)
            f.write(f"Hash     : {d['hash']}\n")
            f.write(f"Type     : {d['type']}\n")
            f.write(f"Category : {d['category']}\n")
            f.write(f"Status   : {d['status']}\n")
            if d.get("password"):
                f.write(f"Password : {d['password']}\n")
            else:
                f.write("Password : (not found)\n")
            f.write(f"Attempts : {d['attempts']:,}\n")
            f.write(f"Time     : {d['time']}s\n")
            f.write(f"Speed    : {d['speed']:,.0f} h/s\n")
            if d.get("error"):
                f.write(f"Error    : {d['error']}\n")
            f.write("-" * 70 + "\n")
        cracked = sum(1 for r in results if r.status == "cracked")
        total = len(results)
        pct = cracked / total * 100 if total else 0
        f.write(f"\nSummary: {cracked}/{total} cracked ({pct:.0f}%)\n")


def _write_json(results: list[CrackResult], path: str) -> None:
    data = {
        "tool": "DonHash",
        "version": "2.0",
        "generated": datetime.now().isoformat(),
        "results": [_result_to_dict(r) for r in results],
        "summary": {
            "total": len(results),
            "cracked": sum(1 for r in results if r.status == "cracked"),
            "not_found": sum(1 for r in results if r.status == "not_found"),
            "unsupported": sum(1 for r in results if r.status == "unsupported"),
            "error": sum(1 for r in results if r.status == "error"),
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _write_csv(results: list[CrackResult], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["hash", "type", "category", "status", "password",
                        "attempts", "time", "speed", "error"],
        )
        writer.writeheader()
        for r in results:
            writer.writerow(_result_to_dict(r))


def _esc(s) -> str:
    """HTML-escape a value for safe embedding in HTML output."""
    return html.escape(str(s) if s is not None else "", quote=True)


def _write_html(results: list[CrackResult], path: str) -> None:
    cracked = sum(1 for r in results if r.status == "cracked")
    total = len(results)
    not_found = sum(1 for r in results if r.status == "not_found")
    unsupported = sum(1 for r in results if r.status == "unsupported")
    errored = sum(1 for r in results if r.status == "error")

    rows_html: list[str] = []
    for r in results:
        d = _result_to_dict(r)
        status_class = "cracked" if d["status"] == "cracked" else "not-found"
        pw_display = _esc(d["password"]) if d.get("password") else "(not found)"
        rows_html.append(
            "<tr>"
            f'<td><code>{_esc(d["hash"][:60])}</code></td>'
            f'<td>{_esc(d["type"])}</td>'
            f'<td>{_esc(d["category"])}</td>'
            f'<td class="{status_class}">{_esc(d["status"])}</td>'
            f'<td class="{status_class}">{pw_display}</td>'
            f'<td>{d["attempts"]:,}</td>'
            f'<td>{d["time"]}s</td>'
            f'<td>{d["speed"]:,.0f} h/s</td>'
            f'<td>{_esc(d.get("error") or "")}</td>'
            "</tr>"
        )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DonHash v2.0 — Cracking Results</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0a0a0a; color: #e0e0e0; margin: 0; padding: 20px; }}
  h1 {{ color: #00ffcc; text-align: center; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; }}
  h2 {{ color: #ff6600; }}
  .summary {{ background: #1a1a2e; padding: 15px; border-radius: 8px; margin: 20px 0; }}
  table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
  th {{ background: #16213e; color: #00ffcc; padding: 12px; text-align: left; }}
  td {{ padding: 10px; border-bottom: 1px solid #333; }}
  tr:hover {{ background: #1a1a2e; }}
  .cracked {{ color: #00ff66; font-weight: bold; }}
  .not-found {{ color: #ff4444; }}
  .footer {{ text-align: center; color: #666; margin-top: 30px; font-size: 0.9em; }}
</style>
</head>
<body>
<h1>DonHash v2.0 — Cracking Results</h1>
<div class="summary">
  <p><strong>Generated:</strong> {_esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>
  <p><strong>Total:</strong> {total} | <strong>Cracked:</strong> {cracked} | <strong>Not Found:</strong> {not_found} | <strong>Unsupported:</strong> {unsupported} | <strong>Errors:</strong> {errored}</p>
</div>
<h2>Results</h2>
<table>
<thead><tr><th>Hash</th><th>Type</th><th>Category</th><th>Status</th><th>Password</th><th>Attempts</th><th>Time</th><th>Speed</th><th>Error</th></tr></thead>
<tbody>
{chr(10).join(rows_html)}
</tbody>
</table>
<div class="footer">DonHash v2.0 | Author: CySec Don | cysecdon@gmail.com</div>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)


def _write_xml(results: list[CrackResult], path: str) -> None:
    root = ET.Element("donhash-results")
    root.set("version", "2.0")
    root.set("generated", datetime.now().isoformat())

    summary = ET.SubElement(root, "summary")
    ET.SubElement(summary, "total").text = str(len(results))
    ET.SubElement(summary, "cracked").text = str(
        sum(1 for r in results if r.status == "cracked")
    )

    for r in results:
        entry = ET.SubElement(root, "result")
        d = _result_to_dict(r)
        for key in ("hash", "type", "category", "status", "password",
                    "attempts", "time", "speed", "error"):
            elem = ET.SubElement(entry, key)
            val = d.get(key, "")
            elem.text = str(val) if val is not None else ""

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="unicode", xml_declaration=True)


def _write_markdown(results: list[CrackResult], path: str) -> None:
    cracked = sum(1 for r in results if r.status == "cracked")
    total = len(results)
    pct = cracked / total * 100 if total else 0
    with open(path, "w", encoding="utf-8") as f:
        f.write("# DonHash v2.0 — Cracking Results\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Summary:** {cracked}/{total} cracked ({pct:.0f}%)\n\n")
        f.write(
            "| Hash | Type | Category | Status | Password | Attempts | Time | Speed | Error |\n"
            "|------|------|----------|--------|----------|----------|------|-------|-------|\n"
        )
        for r in results:
            d = _result_to_dict(r)
            pw = d["password"] if d.get("password") else "(not found)"
            # Escape pipe characters in markdown table
            hash_safe = d["hash"][:50].replace("|", "\\|")
            type_safe = (d["type"] or "").replace("|", "\\|")
            cat_safe = (d["category"] or "").replace("|", "\\|")
            pw_safe = (pw or "").replace("|", "\\|")
            err_safe = (d.get("error") or "").replace("|", "\\|")
            f.write(
                f"| `{hash_safe}` | {type_safe} | {cat_safe} | {d['status']} | "
                f"{pw_safe} | {d['attempts']:,} | {d['time']}s | "
                f"{d['speed']:,.0f} h/s | {err_safe} |\n"
            )
