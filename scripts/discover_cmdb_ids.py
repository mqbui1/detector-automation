#!/usr/bin/env python3
"""
discover_cmdb_ids.py

Queries the Splunk Observability Cloud Dimension API to find all cmdb_id values
seen in your org's telemetry. Also lists teams and global template detectors.

Usage:
    export SPLUNK_ACCESS_TOKEN=<token>
    export SPLUNK_REALM=us1

    python3 scripts/discover_cmdb_ids.py               # list cmdb_ids
    python3 scripts/discover_cmdb_ids.py --teams        # also list teams
    python3 scripts/discover_cmdb_ids.py --detectors    # also list global detectors
    python3 scripts/discover_cmdb_ids.py --all          # everything
"""

import argparse
import os
import sys

import requests

REALM = os.environ.get("SPLUNK_REALM", "us1")
TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
API_BASE = f"https://api.{REALM}.signalfx.com"
HDR = {"X-SF-TOKEN": TOKEN, "Content-Type": "application/json"}


def api_get(path, params=None):
    r = requests.get(f"{API_BASE}{path}", headers=HDR, params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def discover_cmdb_ids():
    """Find all cmdb_id dimension values via Dimension API."""
    print(f"\nQuerying cmdb_id dimensions (realm={REALM})...")
    results = []
    offset = 0
    while True:
        data = api_get("/v2/dimension", {
            "query": "key:cmdb_id",
            "limit": 200,
            "offset": offset,
        })
        batch = data.get("results", [])
        results.extend(batch)
        if len(batch) < 200:
            break
        offset += 200

    if not results:
        print("  No cmdb_id dimensions found.")
        print("  Make sure your services are sending spans with a 'cmdb_id' resource attribute.")
        return []

    values = sorted({d["value"] for d in results})
    print(f"\n  Found {len(values)} cmdb_id value(s):\n")
    for v in values:
        print(f"    {v}")
    return values


def discover_teams():
    """List all Splunk O11y teams with their IDs."""
    print(f"\nQuerying teams (realm={REALM})...")
    data = api_get("/v2/team", {"limit": 200})
    teams = data.get("results", [])
    if not teams:
        print("  No teams found.")
        return []

    print(f"\n  Found {len(teams)} team(s):\n")
    print(f"  {'Team Name':<35} {'Team ID':<20} {'Members':>8}")
    print("  " + "-" * 65)
    for t in sorted(teams, key=lambda x: x.get("name", "")):
        print(f"  {t.get('name','?'):<35} {t.get('id','?'):<20} {len(t.get('members', [])):>8}")
    return teams


def discover_global_detectors(tag="global-template"):
    """List detectors tagged as global templates."""
    print(f"\nQuerying detectors with tag '{tag}' (realm={REALM})...")
    data = api_get("/v2/detector", {"limit": 200, "tags": tag})
    detectors = data.get("results", [])

    if not detectors:
        print(f"  No detectors found with tag '{tag}'.")
        print(f"  Tag your global/template detectors with '{tag}' in the Splunk O11y UI.")
        return []

    print(f"\n  Found {len(detectors)} global template detector(s):\n")
    print(f"  {'Name':<55} {'ID':<15} {'Origin'}")
    print("  " + "-" * 85)
    for d in sorted(detectors, key=lambda x: x.get("name", "")):
        print(f"  {d.get('name','?'):<55} {d.get('id','?'):<15} {d.get('detectorOrigin','Standard')}")
    return detectors


def main():
    if not TOKEN:
        print("Error: SPLUNK_ACCESS_TOKEN not set")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Discover cmdb_ids, teams, and global detectors")
    parser.add_argument("--teams",     action="store_true", help="List all teams and their IDs")
    parser.add_argument("--detectors", action="store_true", help="List global template detectors")
    parser.add_argument("--tag",       default="global-template", help="Tag used to identify global detectors")
    parser.add_argument("--all",       action="store_true", help="Show everything")
    args = parser.parse_args()

    discover_cmdb_ids()

    if args.teams or args.all:
        discover_teams()

    if args.detectors or args.all:
        discover_global_detectors(tag=args.tag)

    print()


if __name__ == "__main__":
    main()
