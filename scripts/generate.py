#!/usr/bin/env python3
"""
generate.py

Reads team_config.yaml + fetches global template detectors from Splunk O11y,
then generates an organized Terraform directory structure:

  terraform/
  ├── main.tf                        # provider config (static, module blocks auto-updated)
  ├── variables.tf                   # variables (static)
  ├── golden/                        # one .tf per global detector — source of truth
  │   ├── apm_latency.tf
  │   └── infra_high_cpu.tf
  └── teams/
      ├── platform/
      │   ├── overrides.yaml         # ← teams edit this to customize their detectors
      │   ├── provider.tf            # provider inheritance (generated, don't edit)
      │   ├── main.tf                # team metadata (generated, don't edit)
      │   ├── apm_latency.tf         # golden + cmdb filter + overrides applied
      │   └── infra_high_cpu.tf
      └── payments/
          ├── overrides.yaml
          ├── provider.tf
          ├── main.tf
          ├── apm_latency.tf
          └── infra_high_cpu.tf

Usage:
    export SPLUNK_ACCESS_TOKEN=<token>
    export SPLUNK_REALM=us1

    python3 scripts/generate.py                   # generate / update all files
    python3 scripts/generate.py --dry-run         # preview without writing
    python3 scripts/generate.py --diff            # show what golden changes would affect team overrides
    python3 scripts/generate.py --diff --team payments  # diff for one team only

After running:
    cd terraform/
    terraform init
    terraform plan
    terraform apply
"""

import argparse
import copy
import difflib
import os
import re
import sys
from pathlib import Path

import requests
import yaml

REALM    = os.environ.get("SPLUNK_REALM", "us1")
TOKEN    = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
API_BASE = f"https://api.{REALM}.signalfx.com"
HDR      = {"X-SF-TOKEN": TOKEN, "Content-Type": "application/json"}

SCRIPT_DIR = Path(__file__).parent
REPO_ROOT  = SCRIPT_DIR.parent

# ANSI colours for diff output
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


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

    explicit_ids = config.get("global_detector_ids", [])
    for det_id in explicit_ids:
        try:
            d = api_get(f"/v2/detector/{det_id}")
            detectors.append(d)
            print(f"  [explicit] {d['name']} ({det_id})")
        except Exception as e:
            print(f"  [warn] Could not fetch detector {det_id}: {e}")

    if not explicit_ids:
        tag  = config.get("global_detector_tag", "global-template")
        data = api_get("/v2/detector", {"limit": 200, "tags": tag})
        for d in data.get("results", []):
            detectors.append(d)
            print(f"  [tag:{tag}] {d['name']} ({d['id']})")

    return detectors


# ---------------------------------------------------------------------------
# Overrides — load and apply
# ---------------------------------------------------------------------------

def load_overrides(team_dir):
    """
    Load teams/<name>/overrides.yaml.
    Returns empty dict if file doesn't exist.

    Schema:
      detectors:
        <detector_slug>:
          disabled: true              # exclude this detector for this team
          severity: Warning           # override severity for ALL rules
          rules:
            - detect_label: "..."     # must match golden detect_label exactly
              severity: Warning       # override severity for this rule
              notifications:          # replace notifications for this rule
                - type: PagerDuty
                  credentialId: abc
              disabled: true          # suppress this specific rule
          extra_filters:              # AND'd with the cmdb_id filter
            - key: sf_environment
              value: production
          tags:                       # additional tags (merged with generated tags)
            - my-custom-tag
          description: "..."          # replace description
    """
    path = Path(team_dir) / "overrides.yaml"
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def apply_overrides(det, team, overrides):
    """
    Merge team overrides onto a deep copy of the golden detector.
    Returns the modified detector dict — does not mutate the original.

    Layers applied (in order):
      1. cmdb_id filter injected into program_text
      2. extra_filters AND'd into the cmdb filter
      3. rule-level overrides (severity, notifications, disabled)
      4. top-level overrides (description, tags, severity)
    """
    d = copy.deepcopy(det)
    det_slug = slug(det["name"])
    det_overrides = (overrides.get("detectors") or {}).get(det_slug, {})

    # Top-level description override
    if "description" in det_overrides:
        d["description"] = det_overrides["description"]

    # Extra filters (AND'd with cmdb filter at program_text injection time)
    d["_extra_filters"] = det_overrides.get("extra_filters", [])

    # Rule-level overrides: build a lookup by detect_label
    rule_overrides = {
        r["detect_label"]: r
        for r in (det_overrides.get("rules") or [])
        if "detect_label" in r
    }

    # Global severity override (applies to all rules unless per-rule overrides exist)
    global_severity = det_overrides.get("severity")

    merged_rules = []
    for rule in d.get("rules", []):
        label = rule.get("detectLabel", "")
        rov   = rule_overrides.get(label, {})

        # Skip disabled rules
        if rov.get("disabled"):
            continue

        r = copy.deepcopy(rule)

        # Severity: per-rule override > global override > golden value
        if "severity" in rov:
            r["severity"] = rov["severity"]
        elif global_severity:
            r["severity"] = global_severity

        # Notifications: full replacement if specified
        if "notifications" in rov:
            r["notifications"] = rov["notifications"]

        merged_rules.append(r)

    d["rules"] = merged_rules

    # Additional tags
    extra_tags = det_overrides.get("tags", [])
    if extra_tags:
        d["_extra_tags"] = extra_tags

    # Mark disabled at detector level
    d["_disabled"] = det_overrides.get("disabled", False)

    return d


def render_overrides_template(detectors):
    """
    Render a commented-out overrides.yaml template showing all available options.
    Only written once when the team directory is first created.
    """
    det_blocks = ""
    for det in detectors:
        s = slug(det["name"])
        rules_block = ""
        for rule in det.get("rules", []):
            label = rule.get("detectLabel", "")
            rules_block += f"""\
      #   - detect_label: "{label}"
      #     severity: Warning           # Critical | Major | Minor | Warning | Info
      #     disabled: false             # set true to suppress this alert rule
      #     notifications:              # replaces golden notifications for this rule
      #       - type: PagerDuty
      #         credentialId: YOUR_CRED_ID
      #       - type: Email
      #         email: oncall@example.com
      #       - type: Slack
      #         credentialId: YOUR_CRED_ID
      #         channel: "#alerts"
"""
        det_blocks += f"""\
  # ── {det['name']} ──
  # {s}:
  #   disabled: false                   # set true to skip this detector for this team
  #   severity: Warning                 # override severity for ALL rules
  #   description: "Custom description"
  #   extra_filters:                    # AND'd with cmdb_id filter in SignalFlow
  #     - key: sf_environment
  #       value: production
  #   tags:
  #     - my-team-tag
  #   rules:
{rules_block}
"""

    return f"""\
# =============================================================================
# Team detector overrides
#
# This file lets your team customize golden detectors without touching
# the golden source or the generated Terraform directly.
#
# How it works:
#   1. Edit this file to express your customizations.
#   2. Run: python3 scripts/generate.py
#   3. Commit the changes to terraform/teams/<name>/*.tf
#   4. Run: cd terraform && terraform apply
#
# When the monitoring team updates a golden detector, re-run generate.py.
# Your overrides are re-applied automatically on top of the new golden version.
#
# All sections are optional. Remove comments to activate an override.
# =============================================================================

detectors:
{det_blocks}\
"""


# ---------------------------------------------------------------------------
# SignalFlow filter injection
# ---------------------------------------------------------------------------

def make_filter_expr(cmdb_ids, extra_filters=None):
    """
    Build the full SignalFlow filter expression:
      filter('cmdb_id', 'APP-001', 'APP-002') [and filter('key', 'val') ...]
    """
    quoted = ", ".join(f"'{v}'" for v in cmdb_ids)
    expr = f"filter('cmdb_id', {quoted})"
    for ef in (extra_filters or []):
        expr = f"({expr} and filter('{ef['key']}', '{ef['value']}'))"
    return expr


def inject_filter(program_text, cmdb_ids, extra_filters=None):
    """
    Inject cmdb_id (+ optional extra) filters into SignalFlow program text.

    Handles three patterns:
      1. AutoDetect fn_detector(filter_=<existing>)  → ANDs new filter with existing
      2. AutoDetect fn_detector()                    → adds filter_=<filter>
      3. Raw data("metric", ...)                     → adds filter= to each data() call
    """
    f_expr = make_filter_expr(cmdb_ids, extra_filters)

    # Pattern 1: existing filter_= → AND
    filter_arg_re = re.compile(r"(filter_\s*=\s*)(filter\([^)]+\))", re.MULTILINE)
    if filter_arg_re.search(program_text):
        return filter_arg_re.sub(
            lambda m: f"{m.group(1)}({f_expr} and {m.group(2)})",
            program_text,
        )

    # Pattern 2: AutoDetect _detector() → inject filter_=
    detector_fn_re = re.compile(r"((?:\w+\.)+\w+_detector)\(([^)]*)\)", re.MULTILINE)
    if detector_fn_re.search(program_text):
        def _inject_fn(m):
            existing = m.group(2).strip()
            args = f"{existing}, filter_={f_expr}" if existing else f"filter_={f_expr}"
            return f"{m.group(1)}({args})"
        return detector_fn_re.sub(_inject_fn, program_text)

    # Pattern 3: raw data() calls
    if "data(" in program_text:
        out_lines = []
        for line in program_text.splitlines():
            m = re.match(r"^(.*?data\()(['\"][^'\"]+['\"])(.*)", line)
            if m:
                prefix, metric, rest = m.group(1), m.group(2), m.group(3)
                if "filter=" in rest:
                    rest = re.sub(
                        r"(filter=)(filter\([^)]+\))",
                        lambda fm: f"{fm.group(1)}({f_expr} and {fm.group(2)})",
                        rest,
                    )
                else:
                    rest = f", filter={f_expr}{rest}"
                out_lines.append(f"{prefix}{metric}{rest}")
            else:
                out_lines.append(line)
        return "\n".join(out_lines)

    return f"# TODO: inject cmdb_id filter manually: {f_expr}\n{program_text}"


# ---------------------------------------------------------------------------
# Terraform rendering helpers
# ---------------------------------------------------------------------------

def tf_escape(s):
    return str(s or "").replace("\\", "\\\\").replace("${", "$${").replace("%{", "%%{")


def slug(text):
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def min_resolution(det):
    resolutions = det.get("labelResolutions") or {}
    vals = list(resolutions.values())
    return vals[0] if vals else 0


def rules_tf(rules):
    """Render rule{} blocks from a list of rule dicts."""
    blocks = []
    for rule in rules:
        notif_lines = [
            f'      "{_notif_to_tf(n)}",'
            for n in rule.get("notifications", [])
            if _notif_to_tf(n)
        ]
        notif_block = (
            "\n    notifications = [\n" + "\n".join(notif_lines) + "\n    ]"
            if notif_lines else ""
        )
        blocks.append(
            f"\n  rule {{\n"
            f"    description  = \"{tf_escape(rule.get('description', ''))}\"\n"
            f"    detect_label = \"{tf_escape(rule.get('detectLabel', ''))}\"\n"
            f"    severity     = \"{rule.get('severity', 'Critical')}\"{notif_block}\n"
            f"  }}"
        )
    return "\n".join(blocks)


def _notif_to_tf(n):
    # Handles both Splunk API format {type, credentialId, ...}
    # and overrides.yaml format {type, credentialId, channel, email, ...}
    t = n.get("type", "")
    if t == "Email":      return f"Email,{n.get('email','')}"
    if t == "PagerDuty":  return f"PagerDuty,{n.get('credentialId','')}"
    if t == "Slack":      return f"Slack,{n.get('credentialId','')},{n.get('channel','')}"
    if t == "Webhook":    return f"Webhook,{n.get('credentialId','')},{n.get('url','')}"
    if t == "ServiceNow": return f"ServiceNow,{n.get('credentialId','')}"
    if t == "Opsgenie":   return f"Opsgenie,{n.get('credentialId','')}"
    if t == "VictorOps":  return f"VictorOps,{n.get('credentialId','')},{n.get('routingKey','')}"
    return ""


def viz_tf(det):
    viz = det.get("visualizationOptions") or {}
    return (
        f"visualization_options {{\n"
        f"    show_data_markers = {str(viz.get('showDataMarkers', True)).lower()}\n"
        f"    show_event_lines  = {str(viz.get('showEventLines', False)).lower()}\n"
        f"  }}"
    )


# ---------------------------------------------------------------------------
# Golden detector rendering  (terraform/golden/<slug>.tf)
# ---------------------------------------------------------------------------

def render_golden_tf(det):
    res     = slug(det["name"])
    tags    = sorted(set((det.get("tags") or []) + ["golden", "global-template"]))
    tags_tf = ", ".join(f'"{t}"' for t in tags)

    return (
        f"# Golden detector — source of truth, no team filter applied.\n"
        f"# Generated by scripts/generate.py from detector ID: {det['id']}\n"
        f"# DO NOT edit by hand. Re-run generate.py to sync changes from Splunk O11y.\n\n"
        f'resource "signalfx_detector" "golden_{res}" {{\n'
        f'  name        = "{tf_escape(det["name"])}"\n'
        f'  description = "{tf_escape(det.get("description", ""))}"\n\n'
        f"  program_options {{\n"
        f"    minimum_resolution = {min_resolution(det)}\n"
        f"  }}\n\n"
        f"  program_text = <<-EOT\n"
        f"{det.get('programText', '').rstrip()}\n"
        f"  EOT\n\n"
        f"  tags = [{tags_tf}]\n\n"
        f"  {viz_tf(det)}\n"
        f"{rules_tf(det.get('rules', []))}\n\n"
        f"  lifecycle {{\n"
        f"    prevent_destroy = true\n"
        f"  }}\n"
        f"}}\n"
    )


# ---------------------------------------------------------------------------
# Team detector rendering  (terraform/teams/<team>/<detector_slug>.tf)
# ---------------------------------------------------------------------------

def render_team_detector_tf(det, team, overrides):
    """
    Render one team detector file.
    det is the golden detector; overrides are loaded from overrides.yaml.
    apply_overrides() merges them before rendering.
    """
    merged     = apply_overrides(det, team, overrides)

    if merged.get("_disabled"):
        return (
            f"# Detector disabled for team {team['name']} via overrides.yaml\n"
            f"# Golden detector: {det['id']} — {det['name']}\n"
        )

    team_name  = team["name"]
    team_id    = team["splunk_team_id"]
    cmdb_ids   = team["cmdb_ids"]
    det_id     = det["id"]
    res        = slug(det["name"])
    name       = f"{det['name']} [{team_name}]"

    extra_filters = merged.get("_extra_filters", [])
    program       = inject_filter(merged.get("programText", ""), cmdb_ids, extra_filters)

    base_tags  = set((det.get("tags") or []) + [f"team:{team_name}", f"golden:{det_id}", "team-scoped"])
    extra_tags = set(merged.get("_extra_tags", []))
    all_tags   = sorted((base_tags | extra_tags) - {"global-template", "golden"})
    tags_tf    = ", ".join(f'"{t}"' for t in all_tags)

    # Build override summary for header comment
    det_slug    = slug(det["name"])
    det_ov      = (overrides.get("detectors") or {}).get(det_slug, {})
    ov_summary  = _override_summary(det_ov)

    return (
        f"# Team-scoped detector for: {team_name}\n"
        f"# cmdb_id(s): {', '.join(cmdb_ids)}\n"
        f"# Cloned from golden detector: {det_id}\n"
        f"# Generated by scripts/generate.py — do not edit by hand.\n"
        + (f"# Overrides applied: {ov_summary}\n" if ov_summary else "")
        + f"\n"
        f'resource "signalfx_detector" "{team_name}_{res}" {{\n'
        f'  name        = "{tf_escape(name)}"\n'
        f'  description = "{tf_escape(merged.get("description", f"Scoped to {team_name} (cmdb_id: {chr(44).join(cmdb_ids)}). Golden: {det_id}"))}"\n\n'
        f"  program_options {{\n"
        f"    minimum_resolution = {min_resolution(merged)}\n"
        f"  }}\n\n"
        f"  program_text = <<-EOT\n"
        f"{program.rstrip()}\n"
        f"  EOT\n\n"
        f'  teams = ["{team_id}"]\n\n'
        f"  tags = [{tags_tf}]\n\n"
        f"  {viz_tf(merged)}\n"
        f"{rules_tf(merged.get('rules', []))}\n\n"
        f"  lifecycle {{\n"
        f"    prevent_destroy = false\n"
        f"  }}\n"
        f"}}\n"
    )


def _override_summary(det_ov):
    """One-line summary of what overrides are active, for the file header comment."""
    parts = []
    if det_ov.get("disabled"):
        return "DISABLED"
    if det_ov.get("severity"):
        parts.append(f"severity={det_ov['severity']}")
    if det_ov.get("description"):
        parts.append("description")
    if det_ov.get("extra_filters"):
        parts.append(f"{len(det_ov['extra_filters'])} extra filter(s)")
    if det_ov.get("tags"):
        parts.append(f"{len(det_ov['tags'])} extra tag(s)")
    if det_ov.get("rules"):
        rule_parts = []
        for r in det_ov["rules"]:
            if r.get("disabled"):
                rule_parts.append(f"rule '{r['detect_label']}' disabled")
            else:
                sub = []
                if "severity" in r:   sub.append(f"severity={r['severity']}")
                if "notifications" in r: sub.append("notifications")
                if sub:
                    rule_parts.append(f"rule '{r['detect_label']}': {', '.join(sub)}")
        parts.extend(rule_parts)
    return ", ".join(parts) if parts else ""


def render_team_main_tf(team, detectors):
    det_names = "\n".join(f"#   - {d['name']}" for d in detectors)
    cmdb_list = "\n".join(f"#   - {c}" for c in team["cmdb_ids"])
    return (
        f"# {'='*77}\n"
        f"# Team: {team['name']}\n"
        f"# Splunk O11y Team ID: {team['splunk_team_id']}\n"
        f"#\n"
        f"# cmdb_ids owned by this team:\n"
        f"{cmdb_list}\n"
        f"#\n"
        f"# Detectors managed in this directory (one .tf file per golden detector):\n"
        f"{det_names}\n"
        f"#\n"
        f"# To customize: edit overrides.yaml, then re-run scripts/generate.py\n"
        f"# To add a detector: tag it 'global-template' in Splunk O11y, re-run generate.py\n"
        f"# {'='*77}\n"
    )


def render_team_provider_tf():
    return (
        "# Provider inheritance — do not edit.\n"
        "terraform {\n"
        "  required_providers {\n"
        "    signalfx = {\n"
        '      source  = "splunk-terraform/signalfx"\n'
        '      version = "~> 9.0"\n'
        "    }\n"
        "  }\n"
        "}\n"
    )


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------

def run_diff(teams, detectors, tf_root, filter_team=None):
    """
    For each team × detector, compare:
      A) What's currently on disk (terraform/teams/<name>/<det>.tf)
      B) What would be generated now (golden + overrides applied)

    Highlights:
      - Lines changed by a golden update (no override protecting them)
      - Lines that differ because of an active override (protected)
      - Files that don't exist yet (new detector)
    """
    teams_dir = tf_root / "teams"
    any_diff  = False

    for team in teams:
        name = team["name"]
        if filter_team and name != filter_team:
            continue
        if not team.get("cmdb_ids") or team.get("splunk_team_id", "").startswith("REPLACE"):
            continue

        team_dir   = teams_dir / name
        overrides  = load_overrides(team_dir)

        print(f"\n{BOLD}{CYAN}{'─'*70}{RESET}")
        print(f"{BOLD}Team: {name}{RESET}  ({', '.join(team['cmdb_ids'])})")

        det_slug_ov = overrides.get("detectors") or {}

        for det in detectors:
            det_slug  = slug(det["name"])
            tf_path   = team_dir / f"{det_slug}.tf"
            new_content = render_team_detector_tf(det, team, overrides)

            if not tf_path.exists():
                print(f"\n  {GREEN}+ {det['name']}{RESET}  [{tf_path.name}]  — NEW (not yet generated)")
                any_diff = True
                continue

            old_content = tf_path.read_text()

            if old_content == new_content:
                print(f"\n  {det['name']}  [{tf_path.name}]  — no changes")
                continue

            any_diff = True
            det_ov   = det_slug_ov.get(det_slug, {})
            ov_summary = _override_summary(det_ov)

            print(f"\n  {YELLOW}~ {det['name']}{RESET}  [{tf_path.name}]")
            if ov_summary:
                print(f"    {CYAN}Overrides active: {ov_summary}{RESET}")

            old_lines = old_content.splitlines(keepends=True)
            new_lines = new_content.splitlines(keepends=True)
            diff = list(difflib.unified_diff(
                old_lines, new_lines,
                fromfile=f"current/{tf_path.name}",
                tofile=f"generated/{tf_path.name}",
                n=2,
            ))

            # Annotate diff lines — flag if a changed line is inside an override block
            _print_annotated_diff(diff, det_ov)

    if not any_diff:
        print(f"\n{GREEN}No changes — all team detectors are up to date.{RESET}")
    else:
        print(f"\n{YELLOW}Run 'python3 scripts/generate.py' to apply changes.{RESET}")
        print(f"{YELLOW}Then 'cd terraform && terraform plan' to preview Splunk O11y changes.{RESET}")


def _print_annotated_diff(diff_lines, det_ov):
    """Print unified diff with colour + annotation for override-protected lines."""
    # Build a set of keywords that indicate an overridden field
    protected_keywords = set()
    if det_ov.get("severity"):
        protected_keywords.add("severity")
    if det_ov.get("description"):
        protected_keywords.add("description")
    for r in (det_ov.get("rules") or []):
        if r.get("notifications"):
            protected_keywords.add("notifications")
        if r.get("severity"):
            protected_keywords.add("severity")

    for line in diff_lines:
        stripped = line.rstrip("\n")
        if stripped.startswith("---") or stripped.startswith("+++"):
            print(f"    {BOLD}{stripped}{RESET}")
        elif stripped.startswith("@@"):
            print(f"    {CYAN}{stripped}{RESET}")
        elif stripped.startswith("-"):
            annotation = ""
            if any(kw in stripped for kw in protected_keywords):
                annotation = f"  {CYAN}← override active{RESET}"
            print(f"    {RED}{stripped}{RESET}{annotation}")
        elif stripped.startswith("+"):
            annotation = ""
            if any(kw in stripped for kw in protected_keywords):
                annotation = f"  {CYAN}← from override{RESET}"
            print(f"    {GREEN}{stripped}{RESET}{annotation}")
        else:
            print(f"    {stripped}")


# ---------------------------------------------------------------------------
# main.tf module block updater
# ---------------------------------------------------------------------------

def _update_main_tf_modules(main_tf_path, active_teams):
    marker_start = "# >>> AUTO-GENERATED TEAM MODULES — do not edit between markers <<<"
    marker_end   = "# >>> END AUTO-GENERATED TEAM MODULES <<<"

    module_blocks = "\n\n".join(
        f'module "team_{t["name"]}" {{\n  source = "./teams/{t["name"]}"\n}}'
        for t in active_teams
    )
    section = f"{marker_start}\n{module_blocks}\n{marker_end}"

    if not main_tf_path.exists():
        return

    content = main_tf_path.read_text()
    if marker_start in content:
        content = re.sub(
            re.escape(marker_start) + r".*?" + re.escape(marker_end),
            section,
            content,
            flags=re.DOTALL,
        )
    else:
        content = content.rstrip() + f"\n\n{section}\n"

    main_tf_path.write_text(content)
    print(f"  [updated] {main_tf_path}  ({len(active_teams)} module block(s))")


# ---------------------------------------------------------------------------
# File I/O helpers
# ---------------------------------------------------------------------------

def write_or_print(path, content, dry_run, printed):
    if dry_run:
        path_str = str(path)
        if path_str not in printed:
            print(f"\n{'='*60}\n# {path}\n{'='*60}")
            print(content)
            printed.add(path_str)
    else:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate organized Terraform from global Splunk O11y detectors"
    )
    parser.add_argument("--config",   default=str(REPO_ROOT / "team_config.yaml"))
    parser.add_argument("--out",      default=str(REPO_ROOT / "terraform"),
                        help="Root terraform directory (default: terraform/)")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Print generated files to stdout, do not write")
    parser.add_argument("--diff",     action="store_true",
                        help="Show what would change vs current on-disk files")
    parser.add_argument("--team",     default=None,
                        help="Limit --diff or generation to one team name")
    args = parser.parse_args()

    if not TOKEN:
        print("Error: SPLUNK_ACCESS_TOKEN not set")
        sys.exit(1)

    with open(args.config) as f:
        config = yaml.safe_load(f)

    teams = config.get("teams", [])
    if not teams:
        print("No teams defined in team_config.yaml.")
        sys.exit(1)

    tf_root   = Path(args.out)
    teams_dir = tf_root / "teams"
    printed   = set()

    print(f"\nFetching global template detectors from realm={REALM}...")
    detectors = fetch_global_detectors(config)
    if not detectors:
        print("\nNo global detectors found.")
        print("  1. Tag template detectors 'global-template' in Splunk O11y UI")
        print("  2. Or add global_detector_ids to team_config.yaml")
        sys.exit(1)

    print(f"\n{len(detectors)} global detector(s) found.\n")

    # ── Diff mode ────────────────────────────────────────────────────────────
    if args.diff:
        run_diff(teams, detectors, tf_root, filter_team=args.team)
        return

    # ── Generate mode ────────────────────────────────────────────────────────

    # golden/
    print("Writing golden detectors...")
    for det in detectors:
        path = tf_root / "golden" / f"{slug(det['name'])}.tf"
        write_or_print(path, render_golden_tf(det), args.dry_run, printed)
        if not args.dry_run:
            print(f"  [golden]  {path}")

    # teams/<name>/
    print("\nWriting team detectors...")
    skipped      = []
    active_teams = []

    for team in teams:
        name = team["name"]
        if args.team and name != args.team:
            continue
        if not team.get("cmdb_ids"):
            skipped.append(f"{name} (no cmdb_ids)")
            continue
        if team.get("splunk_team_id", "").startswith("REPLACE"):
            skipped.append(f"{name} (splunk_team_id not configured)")
            continue

        active_teams.append(team)
        team_dir  = teams_dir / name
        overrides = load_overrides(team_dir)

        # provider.tf and main.tf — always regenerated
        write_or_print(team_dir / "provider.tf", render_team_provider_tf(),      args.dry_run, printed)
        write_or_print(team_dir / "main.tf",     render_team_main_tf(team, detectors), args.dry_run, printed)

        # overrides.yaml — only written if it doesn't exist yet
        ov_path = team_dir / "overrides.yaml"
        if not args.dry_run and not ov_path.exists():
            ov_path.parent.mkdir(parents=True, exist_ok=True)
            ov_path.write_text(render_overrides_template(detectors))
            print(f"  [created] {ov_path}  ← edit this to customize detectors")

        # one .tf per golden detector
        for det in detectors:
            fname = f"{slug(det['name'])}.tf"
            write_or_print(
                team_dir / fname,
                render_team_detector_tf(det, team, overrides),
                args.dry_run, printed,
            )

        if not args.dry_run:
            ov_summary = _active_overrides_summary(overrides, detectors)
            print(f"  [team]    {team_dir}/  "
                  f"(cmdb_ids: {', '.join(team['cmdb_ids'])})"
                  + (f"  overrides: {ov_summary}" if ov_summary else ""))

    if skipped:
        print("\nSkipped:")
        for s in skipped:
            print(f"  [skip] {s}")

    # Update main.tf module blocks
    if not args.dry_run and not args.team and active_teams:
        _update_main_tf_modules(tf_root / "main.tf", active_teams)

    if not args.dry_run:
        tree = "\n".join(
            f"      ├── {t['name']}/"
            for t in active_teams
        )
        print(f"""
Structure written to {tf_root}/:

  {tf_root}/
  ├── main.tf
  ├── variables.tf
  ├── golden/              ← {len(detectors)} golden detector(s)
  └── teams/
{tree}

Next steps:
  cd {tf_root}
  terraform init
  terraform plan
  terraform apply
""")


def _active_overrides_summary(overrides, detectors):
    """Short summary of which detectors have active overrides."""
    active = []
    for det in detectors:
        s  = slug(det["name"])
        ov = (overrides.get("detectors") or {}).get(s, {})
        if ov:
            summary = _override_summary(ov)
            if summary:
                active.append(f"{s}({summary})")
    return ", ".join(active)


if __name__ == "__main__":
    main()
