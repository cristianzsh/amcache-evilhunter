#!/usr/bin/env python3

"""
AmCache-EvilHunter: parse and analyze a Windows Amcache.hve registry hive.
by Cristian Souza (cristianmsbr@gmail.com)
"""

import argparse
import json
import sys
import csv
import re
import os
from pathlib import Path
from functools import lru_cache
from datetime import datetime, timedelta

import requests
from requests.exceptions import HTTPError

from Registry.Registry import Registry as RegistryHive
from Registry.RegistryParse import ParseException as RegistryParseException

from rich.console import Console
from rich.table import Table
from rich.live import Live

VERSION = "0.0.2"
VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"

# Core fields to persist for SHA-1–bearing records
KEEP_FIELDS = {
    # Common uninstall/AppV entries
    "ProgramId", "ProgramInstanceId", "Name", "Version", "Publisher",
    "Language", "InstallDate", "Source", "RootDirPath", "HiddenArp",
    "UninstallString", "RegistryKeyPath", "MsiPackageCode",
    "MsiProductCode", "MsiInstallDate", "(default)", "FilePath",
    # Amcache-specific entries
    "SHA-1", "LowerCaseLongPath", "OriginalFileName", "BinFileVersion",
    "BinaryType", "ProductName", "ProductVersion", "LinkDate",
    "BinProductVersion", "Size", "Usn",
    "IsOsComponent",
    # Computed date
    "RecordDate",
}

console = Console()


def prompt_overwrite(path):
    if path.exists():
        ans = input(f"File {path} exists. Overwrite? [y/N]: ")
        if ans.lower() != 'y':
            print("Aborted: file not overwritten.", file=sys.stderr)
            sys.exit(0)


def find_suspicious(data):
    """
    Keep only records whose FilePath basename exactly matches one of our
    known suspicious executables (case‐insensitive), ends with .exe,
    OR is a one‐letter/one‐digit name, OR looks like a random hex string.
    """
    suspicious_patterns = {
        "lb3", "lockbit", "ryuk", "darkside", "conti",
        "maze", "emotet", "trickbot", "qbot", "cerber",
        "svchost", "scvhost", "svch0st", "svhost",
        "rundll32", "rundll", "explorer", "expl0rer", "expiorer",
        "csrss", "csrs", "winlogon", "winlog0n", "winlogin",
        "lsass", "lsas", "isass", "services", "service", "svces",
        "dllhost", "dihost", "dllhst", "conhost", "conhost1",
        "conhost64", "spoolsv", "splsv", "spools", "taskhostw",
        "taskhost", "taskhost64", "taskhostw1", "wmiprvse",
        "mshta", "mshta32", "wscript", "wscript1", "cscript",
        "cscript5", "regsvr32", "regsvr321",
    }
    hex_re = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)

    filtered = {}
    for cat, recs in data.items():
        keep = {}
        for rec, vals in recs.items():
            fp = vals.get("Name", "")
            name = Path(fp).name.lower()
            if not name.endswith(".exe"):
                continue
            stem = name[:-4]
            if (
                stem in suspicious_patterns
                or len(stem) == 1
                or stem.isdigit()
                or hex_re.match(stem)
            ):
                keep[rec] = vals
        if keep:
            filtered[cat] = keep
    return filtered


class AmcacheParser:
    """Parser for offline Amcache.hve registry hive."""
    def __init__(self, hive_path, start=None, end=None):
        if not hive_path.exists():
            raise FileNotFoundError(f"Hive file not found: {hive_path}")
        try:
            self.registry = RegistryHive(str(hive_path))
        except RegistryParseException:
            console.print(
                f"[bold red]Error:[/] '{hive_path}' is not a valid registry hive.",
                style="red"
            )
            sys.exit(1)

        self.start = start
        self.end = end

    def compute_record_date(self, vals, rec_key):
        """Convert Windows FILETIME values to datetime, fallback to key timestamp."""
        def filetime_to_dt(ft_raw):
            try:
                if isinstance(ft_raw, bytes):
                    ft_int = int.from_bytes(ft_raw, "little", signed=False)
                elif isinstance(ft_raw, int):
                    ft_int = ft_raw
                else:
                    return None
                return datetime(1601, 1, 1) + timedelta(microseconds=ft_int // 10)
            except (TypeError, ValueError):
                return None

        for fname in ("LastModifiedTime", "LastWriteTime", "ModifiedTime", "CreationTime"):
            dt = filetime_to_dt(vals.get(fname))
            if dt:
                return dt
        return rec_key.timestamp()

    def parse(self):
        """Walk the Amcache hive and collect record values."""
        root = self.registry.open("Root")
        subs = {k.name(): k for k in root.subkeys()}
        parent = subs.get("InventoryApplicationFile") or subs.get("File") or root

        data = {"Amcache": {}}
        for rec in parent.subkeys():
            vals = {v.name(): v.value() for v in rec.values()}
            vals["FilePath"] = vals.get("LowerCaseLongPath", rec.name())

            record_dt = self.compute_record_date(vals, rec)
            vals["RecordDate"] = record_dt.isoformat()

            if "FileId" in vals:
                vals["SHA-1"] = vals.pop("FileId")

            rd = record_dt.date()
            if self.start and rd < self.start.date():
                continue
            if self.end and rd > self.end.date():
                continue

            data["Amcache"][rec.name()] = vals

        return data


def normalize_data(data):
    """Trim whitespace on all strings; strip leading zeros on SHA-1."""
    for recs in data.values():
        for vals in recs.values():
            for k, v in list(vals.items()):
                if isinstance(v, str):
                    nv = v.strip()
                    if k in ("SHA-1", "SHA1") and nv.startswith("0000"):
                        nv = nv[4:]
                    vals[k] = nv


def prune_record(vals, vt_enabled):
    """Select only the KEEP_FIELDS (plus VT fields) from vals."""
    if not vals.get("SHA-1"):
        return {}
    out = {}
    fields = set(KEEP_FIELDS)
    if vt_enabled:
        fields.update({"VT_Detections", "VT_TotalEngines", "VT_Ratio"})
    for field in fields:
        if field == "IsOsComponent":
            continue
        if field in vals:
            out[field] = vals[field]
    out["IsOsComponent"] = bool(vals.get("IsOsComponent"))
    return out


@lru_cache(maxsize=1024)
def lookup_vt(hash_value, api_key):
    """Fetch VT stats for a hash; return (detections, total, ratio)."""
    try:
        resp = requests.get(
            VT_API_URL.format(hash=hash_value),
            headers={"x-apikey": api_key},
            timeout=15
        )
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        det = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.get(k, 0) for k in stats)
        return det, total, f"{det}/{total}"
    except HTTPError as e:
        if e.response and e.response.status_code == 404:
            return None, None, "N/A"
        return None, None, ""
    except (ValueError, KeyError):
        return None, None, ""


def write_json(path, data, vt_enabled, api_key):
    """Write filtered records to JSON file."""
    prompt_overwrite(path)

    with path.open("w", encoding="utf-8") as f:
        for cat, recs in data.items():
            for rec_name, vals in recs.items():
                kept = prune_record(vals, vt_enabled)
                if not kept:
                    continue

                if vt_enabled:
                    det, tot, ratio = lookup_vt(kept["SHA-1"], api_key)
                    kept["VT_Detections"] = det
                    kept["VT_TotalEngines"] = tot
                    kept["VT_Ratio"] = ratio

                kept["Category"] = cat
                kept["RecordName"] = rec_name
                f.write(json.dumps(kept, ensure_ascii=False) + "\n")


def write_csv(path, data, vt_enabled, api_key):
    """Write filtered records to CSV file."""
    prompt_overwrite(path)

    headers = ["Category", "RecordName", "SHA-1"]
    other = [f for f in KEEP_FIELDS if f not in {"SHA-1", "FilePath"}]
    headers += sorted(other) + ["FilePath"]
    if vt_enabled:
        headers += ["VT_Detections", "VT_TotalEngines", "VT_Ratio"]

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()

        for cat, recs in data.items():
            for rec_name, vals in recs.items():
                kept = prune_record(vals, vt_enabled)
                if not kept:
                    continue

                row = {
                    "Category": cat,
                    "RecordName": rec_name,
                    **kept
                }

                if vt_enabled:
                    det, tot, ratio = lookup_vt(kept["SHA-1"], api_key)
                    row["VT_Detections"] = det
                    row["VT_TotalEngines"] = tot
                    row["VT_Ratio"] = ratio

                writer.writerow(row)


def print_table(data, vt_enabled, api_key=None, only_detections=False):
    """Live-render a table of records; optionally filter VT detections."""
    any_printed = False
    rows_to_print = []

    def make_table():
        tbl = Table(show_header=True, header_style="bold cyan", expand=True)
        tbl.add_column("SHA-1", style="dim")
        tbl.add_column("Name")
        tbl.add_column("RecordDate", justify="center")
        tbl.add_column("OS?", justify="center")
        if vt_enabled:
            tbl.add_column("VT", justify="right")
        return tbl

    table = make_table()
    with Live(table, console=console, refresh_per_second=4) as live:
        for recs in data.values():
            for vals in recs.values():
                sha = vals.get("SHA-1")
                if not sha:
                    continue
                name = vals.get("Name", "")
                record_date_str = vals.get("RecordDate", "")
                try:
                    datetime.fromisoformat(record_date_str)
                except ValueError:
                    pass

                os_flag = "Yes" if vals.get("IsOsComponent") else "No"
                vt_cell = ""
                style = None
                if vt_enabled and api_key:
                    det, _, vt_cell = lookup_vt(sha, api_key)
                    if det and det > 0:
                        style = "bold red"
                    if only_detections and (det is None or det == 0):
                        continue

                row = [sha, name, record_date_str, os_flag]
                if vt_enabled:
                    row.append(vt_cell)

                rows_to_print.append((record_date_str, row, style))
                rows_to_print.sort(key=lambda t: t[0])

                table = make_table()
                for _, r, st in rows_to_print:
                    table.add_row(*r, style=st)
                live.update(table)
                any_printed = True

    if not any_printed:
        msg = "No entries found."
        if vt_enabled and only_detections:
            msg = "No entries with VT detections found."
        console.print(f"[bold red]{msg}[/]")
        sys.exit(1 if vt_enabled and only_detections else 0)


def main():
    """CLI entry point for amcache_evilhunter."""
    parser = argparse.ArgumentParser(
        description="AmCache-EvilHunter: parse and analyze a Windows Amcache.hve registry hive.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"AmCache-EvilHunter {VERSION} by Cristian Souza (cristianmsbr@gmail.com)"
    )
    parser.add_argument('-V', '--version', action='version',
                        version=f"AmCache-EvilHunter {VERSION} by Cristian Souza")
    parser.add_argument("-i", "--input", type=Path, required=True, help="Path to Amcache.hve")
    parser.add_argument("--start", type=str, help="YYYY-MM-DD; only records on or after this date")
    parser.add_argument("--end", type=str, help="YYYY-MM-DD; only records on or before this date")
    parser.add_argument("--search", type=str, help="Comma-separated terms (case-insensitive)")
    parser.add_argument("--find-suspicious", action="store_true",
                        help="Filter only records matching known suspicious patterns")
    parser.add_argument("--exclude-os", action="store_true", help="Only include non-OS-component files")
    parser.add_argument("-v", "--vt", action="store_true",
                        help="Enable VirusTotal lookups (requires VT_API_KEY)")
    parser.add_argument("--only-detections", action="store_true",
                        help="Show/save only files with ≥1 VT detection")
    parser.add_argument("--json", type=Path, help="Path to write JSON Lines")
    parser.add_argument("--csv", type=Path, help="Path to write CSV")
    args = parser.parse_args()

    api_key = None
    if args.vt:
        api_key = os.getenv("VT_API_KEY")
        if not api_key:
            console.print("[bold red]Error:[/] VT_API_KEY environment variable not set", style="red")
            sys.exit(1)

    start_dt = None
    end_dt = None
    if args.start:
        try:
            start_dt = datetime.strptime(args.start, "%Y-%m-%d")
        except ValueError:
            console.print("[bold red]Error:[/] --start must be YYYY-MM-DD", style="red")
            sys.exit(1)
    if args.end:
        try:
            end_dt = datetime.strptime(args.end, "%Y-%m-%d")
        except ValueError:
            console.print("[bold red]Error:[/] --end must be YYYY-MM-DD", style="red")
            sys.exit(1)
    if start_dt and end_dt and start_dt > end_dt:
        console.print("[bold red]Error:[/] --start must be on or before --end", style="red")
        sys.exit(1)

    search_terms = None
    if args.search:
        search_terms = [t.strip().lower() for t in args.search.split(",") if t.strip()]

    try:
        parser = AmcacheParser(args.input, start_dt, end_dt)
        data = parser.parse()
        normalize_data(data)

        if search_terms:
            filtered = {}
            for cat, recs in data.items():
                keep = {
                    rec: vals
                    for rec, vals in recs.items()
                    if any(term in vals.get("FilePath", "").lower() for term in search_terms)
                }
                if keep:
                    filtered[cat] = keep
            data = filtered

        # filter suspicious patterns
        if args.find_suspicious:
            data = find_suspicious(data)

        if args.exclude_os:
            filtered = {}
            for cat, recs in data.items():
                keep = {rec: vals for rec, vals in recs.items() if not vals.get("IsOsComponent")}
                if keep:
                    filtered[cat] = keep
            data = filtered

        print_table(data, vt_enabled=args.vt, api_key=api_key, only_detections=args.only_detections)

        if args.json:
            write_json(args.json, data, vt_enabled=args.vt, api_key=api_key)
        if args.csv:
            write_csv(args.csv, data, vt_enabled=args.vt, api_key=api_key)

    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/] {e}", style="red")
        sys.exit(1)
    except HTTPError as e:
        console.print(f"[bold red]HTTP error:[/] {e}", style="red")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Operation cancelled by user.[/]")
        sys.exit(0)
