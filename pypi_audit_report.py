#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import sys
from typing import Iterable, List, Dict, Any, Optional

def parse_any_json_stream(text: str) -> List[Any]:
    """
    Try multiple strategies to extract JSON values from a text blob.
    Returns a list of top-level JSON values (dicts/lists/others).
    Strategies:
      1) Single full JSON value (json.loads)
      2) JSON Lines (one JSON value per line)
      3) Concatenated JSON objects/arrays using JSONDecoder.raw_decode loop
    """
    # 1) Single JSON value
    try:
        val = json.loads(text)
        return [val]
    except json.JSONDecodeError:
        pass

    # 2) JSON Lines
    values = []
    json_lines_candidate = False
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        json_lines_candidate = True
        try:
            values.append(json.loads(s))
        except json.JSONDecodeError:
            values = []
            json_lines_candidate = False
            break
    if json_lines_candidate and values:
        return values

    # 3) Concatenated JSON values (no commas/whitespace between)
    decoder = json.JSONDecoder()
    idx = 0
    n = len(text)
    values = []
    while idx < n:
        # Skip whitespace
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n:
            break
        try:
            val, next_idx = decoder.raw_decode(text, idx)
            values.append(val)
            idx = next_idx
        except json.JSONDecodeError:
            # unrecoverable
            values = []
            break
    if values:
        return values

    raise ValueError("Could not parse JSON content. Ensure the file is valid JSON, JSON Lines, or concatenated JSON.")

def flatten_results(val: Any) -> Iterable[Dict[str, Any]]:
    """
    Yield audit result dicts from various shapes:
      - A single result dict (with 'package')
      - A list of result dicts
      - An object with 'results' key containing list of dicts
    """
    if isinstance(val, dict):
        if "package" in val or ("info" in val and isinstance(val["info"], dict) and "name" in val["info"]):
            yield val
        elif "results" in val and isinstance(val["results"], list):
            for item in val["results"]:
                if isinstance(item, dict):
                    yield item
    elif isinstance(val, list):
        for item in val:
            if isinstance(item, dict):
                yield item

def extract_row(rec: Dict[str, Any]) -> Optional[List[Any]]:
    """
    Map a single audit record to CSV row.
    Skips records that contain an 'error' key.
    """
    if "error" in rec:
        return None
    package = rec.get("package") or (rec.get("info", {}) or {}).get("name") or ""
    score_total_good = rec.get("score_total_good")
    health_percent = rec.get("health_percent")
    risk_level = rec.get("risk_level")
    return [package, score_total_good, health_percent, risk_level]

def collect_rows_from_text(text: str) -> List[List[Any]]:
    rows: List[List[Any]] = []
    for val in parse_any_json_stream(text):
        for rec in flatten_results(val):
            row = extract_row(rec)
            if row is not None:
                rows.append(row)
    return rows

def main():
    ap = argparse.ArgumentParser(description="Generate CSV from pypi_audit JSON outputs (robust merged/concatenated support).")
    ap.add_argument("inputs", nargs="+", help="One or more JSON files (can be merged, JSONL, or concatenated).")
    ap.add_argument("-o", "--out", default=None, help="Output CSV path. If omitted and --stdout is not set, uses report.csv")
    ap.add_argument("--stdout", action="store_true", help="Write CSV to stdout instead of a file.")
    args = ap.parse_args()

    all_rows: List[List[Any]] = []
    for path in args.inputs:
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        except OSError as e:
            print(f"ERROR: failed to read '{path}': {e}", file=sys.stderr)
            sys.exit(1)
        try:
            rows = collect_rows_from_text(text)
        except Exception as e:
            print(f"ERROR: failed to parse '{path}': {e}", file=sys.stderr)
            sys.exit(1)
        all_rows.extend(rows)

    # Header per user spec
    header = ["package", "score_total_good", "health_percent", "risk_level"]

    if args.stdout:
        w = csv.writer(sys.stdout)
        w.writerow(header)
        w.writerows(all_rows)
        return

    out_path = args.out or "report.csv"
    try:
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(all_rows)
    except OSError as e:
        print(f"ERROR: failed to write '{out_path}': {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Wrote {len(all_rows)} rows to {out_path}")

if __name__ == "__main__":
    main()
