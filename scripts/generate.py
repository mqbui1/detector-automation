#!/usr/bin/env python3
"""
generate.py

Reads team_config.yaml + fetches global template detectors from Splunk O11y,
then generates a Terraform .tf file per team containing cloned, filtered detectors.

Usage:
    export SPLUNK_ACCESS_TOKEN=<token>
    export SPLUNK_REALM=us1
    python3 scripts/generate.py [--config path/to/team_config.yaml] [--out terraform/]

After running, cd terraform/ && terraform apply.
"""

import argparse
import os
import re
import sys
from pathlib import Path

import requests
import yaml

REALM = os.environ.get("SPLUNK_REALM", "us1")
TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
API_BASE = f"https://api.{REALM}.signalfx.com"
HDR = {"X-SF-TOKEN": TOKEN, "Content-Type": "application/json"}

SCRIPT_DIR = Path(__file__).parent
REPO_ROOT  = SCRIPT_DIR.parent


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def api_get(path, params=None):
    r = requests.get(f"{API_BASE}{path}", headers=HDR, params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def fetch_global_detectors(config):
    """Fetch detector objects for all global templates defined in config."""
    detectors = []

    # Option 1: explicit IDs
    explicit_ids = config.get("global_detector_ids", [])
    for det_id in explicit_ids:
        try:
            d = api_get(f"/v2/detector/{det_id}")
            detectors.append(d)
            print(f"  [explicit] {d['name']} ({det_id})")
        except Exception as e:
            print(f"  [warn] Could not fetch detector {det_id}: {e}")

    # Option 2: by tag
    tag = config.get("global_detector_tag", "global-template")
    if not explicit_ids:
        data = api_get("/v2/detector", {"limit": 200, "tags": tag})
        tagged = data.get("results", [])
        for d in tagged:
            detectors.append(d)
            print(f"  [tag:{tag}] {d['name']} ({d['id']})")

    return detectors


# ---------------------------------------------------------------------------
# SignalFlow filter injection
# ---------------------------------------------------------------------------

def make_cmdb_filter(cmdb_ids):
    """
    Build a SignalFlow filter expression for the given cmdb_id list.
    Multiple values are OR'd within a single filter() call.
    e.g. filter('cmdb_id', 'APP-001', 'APP-002')
    """
    quoted = ", ".join(f"'{v}'" for v in cmdb_ids)
    return f"filter('cmdb_id', {quoted})"


def inject_filter(program_text, cmdb_ids):
    """
    Inject a cmdb_id filter into a detector's SignalFlow program text.

    Handles three common patterns:
      1. AutoDetect-style: fn_detector(filter_=<existing>)
         → ANDs the cmdb filter with existing
      2. AutoDetect-style: fn_detector() with no filter_ arg
         → adds filter_=<cmdb_filter>
      3. Raw detect(when(data(...).percentile(...)...)):
         → wraps each data() / stream() call with the filter

    Returns the modified program text.
    """
    cmdb_filter = make_cmdb_filter(cmdb_ids)

    # Pattern 1: already has filter_=... argument
    # e.g. fn_detector(filter_=filter('sf_environment', 'prod'))
    filter_arg_re = re.compile(r"(filter_\s*=\s*)(filter\([^)]+\))", re.MULTILINE)
    if filter_arg_re.search(program_text):
        def replace_filter_arg(m):
            return f"{m.group(1)}({cmdb_filter} and {m.group(2)})"
        return filter_arg_re.sub(replace_filter_arg, program_text)

    # Pattern 2: fn_detector() or fn_detector(some_other_arg=...) — no filter_
    # Find the last function call that ends with .publish(...) chain
    # Look for _detector( calls (AutoDetect pattern)
    detector_fn_re = re.compile(
        r"(\w+\.)+(\w+_detector)\(([^)]*)\)",
        re.MULTILINE,
    )
    if detector_fn_re.search(program_text):
        def inject_into_fn(m):
            existing_args = m.group(3).strip()
            if existing_args:
                return f"{m.group(0)[:-len(m.group(3))-1]}{existing_args}, filter_={cmdb_filter})"
            else:
                return f"{m.group(0)[:-1]}filter_={cmdb_filter})"
        return detector_fn_re.sub(inject_into_fn, program_text)

    # Pattern 3: raw SignalFlow with data() / stream() calls
    # Inject filter as extra filter argument to each data() call.
    # Use a line-by-line approach to handle nested parens correctly.
    if "data(" in program_text:
        out_lines = []
        for line in program_text.splitlines():
            # Match: ...data('metric') or ...data("metric") with optional args
            m = re.match(r"^(.*?data\()(['\"][^'\"]+['\"])(.*)", line)
            if m and "data(" in line:
                prefix   = m.group(1)   # everything up to and including "data("
                metric   = m.group(2)   # the metric name string
                rest     = m.group(3)   # remaining args + closing paren
                if "filter=" in rest:
                    # AND cmdb filter into existing filter= argument
                    rest = re.sub(
                        r"(filter=)(filter\([^)]+\))",
                        lambda fm: f"{fm.group(1)}({cmdb_filter} and {fm.group(2)})",
                        rest,
                    )
                    out_lines.append(f"{prefix}{metric}{rest}")
                else:
                    # Prepend filter= before first comma or closing paren
                    out_lines.append(f"{prefix}{metric}, filter={cmdb_filter}{rest}")
            else:
                out_lines.append(line)
        return "\n".join(out_lines)

    # Fallback: prepend a comment and return unchanged — operator must fix manually
    return (
        f"# TODO: manually inject cmdb_id filter: {cmdb_filter}\n"
        + program_text
    )


# ---------------------------------------------------------------------------
# Terraform generation
# ---------------------------------------------------------------------------

def tf_escape(s):
    """Escape a string for use inside a Terraform heredoc / string."""
    return s.replace("\\", "\\\\").replace("${", "$${").replace("%{", "%%{")


def resource_name(team_name, detector_name):
    """
    Generate a valid Terraform resource name from team + detector name.
    e.g. "platform" + "APM - High error rate" → "platform_apm_high_error_rate"
    """
    combined = f"{team_name}_{detector_name}"
    # lowercase, replace non-alphanumeric with _
    clean = re.sub(r"[^a-z0-9]+", "_", combined.lower()).strip("_")
    return clean


def render_team_tf(team, detectors):
    """
    Render a complete Terraform file for one team containing one
    signalfx_detector resource per global detector.
    """
    team_name     = team["name"]
    team_id       = team["splunk_team_id"]
    cmdb_ids      = team["cmdb_ids"]

    lines = [
        f"# Auto-generated by scripts/generate.py — do not edit by hand",
        f"# Team: {team_name}  |  cmdb_ids: {', '.join(cmdb_ids)}",
        f"",
    ]

    for det in detectors:
        original_name  = det["name"]
        original_id    = det["id"]
        modified_text  = inject_filter(det.get("programText", ""), cmdb_ids)
        res_name       = resource_name(team_name, original_name)
        detector_name  = f"{original_name} [{team_name}]"

        # Build rules blocks
        rules_blocks = []
        for rule in det.get("rules", []):
            severity    = rule.get("severity", "Critical")
            detect_label = rule.get("detectLabel", "")
            description  = rule.get("description", "")
            notifications = rule.get("notifications", [])

            notif_lines = []
            for n in notifications:
                # Splunk O11y notification objects → Terraform string format
                notif_str = _notification_to_tf(n)
                if notif_str:
                    notif_lines.append(f'      "{notif_str}",')

            notif_block = ""
            if notif_lines:
                notif_block = "\n    notifications = [\n" + "\n".join(notif_lines) + "\n    ]\n"

            rules_blocks.append(f"""
  rule {{
    description   = "{tf_escape(description)}"
    detect_label  = "{tf_escape(detect_label)}"
    severity      = "{severity}"{notif_block}
  }}""")

        rules_tf = "\n".join(rules_blocks)

        # Tags: preserve originals + add team/cmdb markers
        original_tags = det.get("tags", []) or []
        extra_tags = [f"team:{team_name}", f"generated-from:{original_id}", "team-scoped"]
        all_tags = sorted(set(original_tags + extra_tags) - {"global-template"})
        tags_tf = ", ".join(f'"{t}"' for t in all_tags)

        # viz options
        viz = det.get("visualizationOptions", {}) or {}
        show_markers    = str(viz.get("showDataMarkers", True)).lower()
        show_event_lines = str(viz.get("showEventLines", False)).lower()

        lines.append(f"""
resource "signalfx_detector" "{res_name}" {{
  name        = "{tf_escape(detector_name)}"
  description = "Team-scoped detector for {team_name} (cmdb_id: {', '.join(cmdb_ids)}). Global detector: {original_id}"

  program_options {{
    minimum_resolution = {det.get('labelResolutions', {}).get(list(det.get('labelResolutions', {}).keys())[0], 0) if det.get('labelResolutions') else 0}
  }}

  program_text = <<-EOT
{modified_text.rstrip()}
  EOT

  teams = ["{team_id}"]

  tags = [{tags_tf}]

  visualization_options {{
    show_data_markers  = {show_markers}
    show_event_lines   = {show_event_lines}
  }}
{rules_tf}

  lifecycle {{
    # Prevent accidental destruction of active team detectors
    prevent_destroy = false
    ignore_changes  = [
      # Ignore manual notification changes made in the UI
      # Remove this if you want Terraform to own notifications fully
    ]
  }}
}}
""")

    return "\n".join(lines)


def _notification_to_tf(n):
    """Convert a Splunk O11y notification object to Terraform notification string."""
    ntype = n.get("type", "")
    if ntype == "Email":
        return f"Email,{n.get('email','')}"
    if ntype == "PagerDuty":
        return f"PagerDuty,{n.get('credentialId','')}"
    if ntype == "Slack":
        return f"Slack,{n.get('credentialId','')},{n.get('channel','')}"
    if ntype == "Webhook":
        return f"Webhook,{n.get('credentialId','')},{n.get('url','')}"
    if ntype == "ServiceNow":
        return f"ServiceNow,{n.get('credentialId','')}"
    if ntype == "Opsgenie":
        return f"Opsgenie,{n.get('credentialId','')}"
    if ntype == "VictorOps":
        return f"VictorOps,{n.get('credentialId','')},{n.get('routingKey','')}"
    return ""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate per-team Terraform from global detectors")
    parser.add_argument("--config", default=str(REPO_ROOT / "team_config.yaml"),
                        help="Path to team_config.yaml")
    parser.add_argument("--out", default=str(REPO_ROOT / "terraform"),
                        help="Output directory for generated .tf files")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print generated Terraform to stdout, do not write files")
    args = parser.parse_args()

    if not TOKEN:
        print("Error: SPLUNK_ACCESS_TOKEN not set")
        sys.exit(1)

    # Load config
    with open(args.config) as f:
        config = yaml.safe_load(f)

    teams = config.get("teams", [])
    if not teams:
        print("No teams defined in config. Edit team_config.yaml first.")
        sys.exit(1)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Fetch global detectors
    print(f"\nFetching global template detectors from realm={REALM}...")
    detectors = fetch_global_detectors(config)

    if not detectors:
        print("\nNo global detectors found. Either:")
        print("  1. Tag template detectors with 'global-template' in the Splunk O11y UI")
        print("  2. Add global_detector_ids to team_config.yaml")
        sys.exit(1)

    print(f"\n{len(detectors)} global detector(s) found.")

    # Generate per-team Terraform
    generated = []
    for team in teams:
        name = team["name"]
        if not team.get("cmdb_ids"):
            print(f"  [skip] {name} — no cmdb_ids defined")
            continue
        if team.get("splunk_team_id", "").startswith("REPLACE"):
            print(f"  [skip] {name} — splunk_team_id not set (still placeholder)")
            continue

        tf_content = render_team_tf(team, detectors)

        if args.dry_run:
            print(f"\n{'='*60}")
            print(f"# team_{name}.tf")
            print('='*60)
            print(tf_content)
        else:
            out_path = out_dir / f"team_{name}.tf"
            out_path.write_text(tf_content)
            generated.append(out_path)
            print(f"  [wrote] {out_path}  ({len(detectors)} detector(s) × {len(team['cmdb_ids'])} cmdb_id(s))")

    if not args.dry_run and generated:
        print(f"\nGenerated {len(generated)} file(s) in {out_dir}/")
        print("\nNext steps:")
        print(f"  cd {out_dir}")
        print(f"  terraform init")
        print(f"  terraform plan")
        print(f"  terraform apply")


if __name__ == "__main__":
    main()
