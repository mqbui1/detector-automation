#!/usr/bin/env python3
"""
generate.py

Reads team_config.yaml + fetches global template detectors from Splunk O11y,
then generates an organized Terraform directory structure:

  terraform/
  ├── main.tf                        # provider config (static)
  ├── variables.tf                   # variables (static)
  ├── golden/                        # one .tf per global detector (source of truth)
  │   ├── apm_latency.tf
  │   └── infra_high_cpu.tf
  └── teams/
      ├── platform/                  # one .tf per detector, filtered to platform's cmdb_ids
      │   ├── main.tf                # team metadata (team ID, cmdb_ids)
      │   ├── apm_latency.tf
      │   └── infra_high_cpu.tf
      └── payments/
          ├── main.tf
          ├── apm_latency.tf
          └── infra_high_cpu.tf

Usage:
    export SPLUNK_ACCESS_TOKEN=<token>
    export SPLUNK_REALM=us1
    python3 scripts/generate.py [--config team_config.yaml] [--out terraform/]
    python3 scripts/generate.py --dry-run

After running:
    cd terraform/
    terraform init
    terraform plan
    terraform apply
"""

import argparse
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

    # Option 1: explicit IDs (takes precedence)
    explicit_ids = config.get("global_detector_ids", [])
    for det_id in explicit_ids:
        try:
            d = api_get(f"/v2/detector/{det_id}")
            detectors.append(d)
            print(f"  [explicit] {d['name']} ({det_id})")
        except Exception as e:
            print(f"  [warn] Could not fetch detector {det_id}: {e}")

    # Option 2: by tag
    if not explicit_ids:
        tag  = config.get("global_detector_tag", "global-template")
        data = api_get("/v2/detector", {"limit": 200, "tags": tag})
        for d in data.get("results", []):
            detectors.append(d)
            print(f"  [tag:{tag}] {d['name']} ({d['id']})")

    return detectors


# ---------------------------------------------------------------------------
# SignalFlow filter injection
# ---------------------------------------------------------------------------

def make_cmdb_filter(cmdb_ids):
    """
    Build a SignalFlow filter expression for a list of cmdb_ids.
    Multiple values are OR'd within one filter() call:
      filter('cmdb_id', 'APP-001', 'APP-002')
    """
    quoted = ", ".join(f"'{v}'" for v in cmdb_ids)
    return f"filter('cmdb_id', {quoted})"


def inject_filter(program_text, cmdb_ids):
    """
    Inject a cmdb_id filter into a detector's SignalFlow program text.

    Handles three patterns in priority order:
      1. AutoDetect fn_detector(filter_=<existing>)  → ANDs cmdb filter with existing
      2. AutoDetect fn_detector()                    → adds filter_=<cmdb_filter>
      3. Raw data("metric", ...)                     → adds filter= to each data() call

    Returns modified program text.
    """
    cmdb_filter = make_cmdb_filter(cmdb_ids)

    # Pattern 1: existing filter_= argument → AND with cmdb filter
    filter_arg_re = re.compile(r"(filter_\s*=\s*)(filter\([^)]+\))", re.MULTILINE)
    if filter_arg_re.search(program_text):
        return filter_arg_re.sub(
            lambda m: f"{m.group(1)}({cmdb_filter} and {m.group(2)})",
            program_text,
        )

    # Pattern 2: AutoDetect _detector() call with no filter_ → inject filter_=
    detector_fn_re = re.compile(r"((?:\w+\.)+\w+_detector)\(([^)]*)\)", re.MULTILINE)
    if detector_fn_re.search(program_text):
        def _inject_fn(m):
            existing = m.group(2).strip()
            args = f"{existing}, filter_={cmdb_filter}" if existing else f"filter_={cmdb_filter}"
            return f"{m.group(1)}({args})"
        return detector_fn_re.sub(_inject_fn, program_text)

    # Pattern 3: raw data("metric") calls — inject filter= per line
    if "data(" in program_text:
        out_lines = []
        for line in program_text.splitlines():
            m = re.match(r"^(.*?data\()(['\"][^'\"]+['\"])(.*)", line)
            if m:
                prefix, metric, rest = m.group(1), m.group(2), m.group(3)
                if "filter=" in rest:
                    rest = re.sub(
                        r"(filter=)(filter\([^)]+\))",
                        lambda fm: f"{fm.group(1)}({cmdb_filter} and {fm.group(2)})",
                        rest,
                    )
                else:
                    rest = f", filter={cmdb_filter}{rest}"
                out_lines.append(f"{prefix}{metric}{rest}")
            else:
                out_lines.append(line)
        return "\n".join(out_lines)

    # Fallback: leave a TODO comment for manual review
    return f"# TODO: inject cmdb_id filter manually: {cmdb_filter}\n{program_text}"


# ---------------------------------------------------------------------------
# Terraform rendering helpers
# ---------------------------------------------------------------------------

def tf_escape(s):
    """Escape string for Terraform heredoc / double-quoted string."""
    return str(s or "").replace("\\", "\\\\").replace("${", "$${").replace("%{", "%%{")


def slug(text):
    """Convert any string to a valid Terraform resource name slug."""
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def min_resolution(det):
    resolutions = det.get("labelResolutions") or {}
    vals = list(resolutions.values())
    return vals[0] if vals else 0


def rules_tf(det):
    """Render rule{} blocks for a detector."""
    blocks = []
    for rule in det.get("rules", []):
        notif_lines = [
            f'      "{_notif_to_tf(n)}",'
            for n in rule.get("notifications", [])
            if _notif_to_tf(n)
        ]
        notif_block = (
            "\n    notifications = [\n" + "\n".join(notif_lines) + "\n    ]"
            if notif_lines else ""
        )
        blocks.append(f"""
  rule {{
    description  = "{tf_escape(rule.get('description', ''))}"
    detect_label = "{tf_escape(rule.get('detectLabel', ''))}"
    severity     = "{rule.get('severity', 'Critical')}"{notif_block}
  }}""")
    return "\n".join(blocks)


def _notif_to_tf(n):
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
    """
    Render a golden (global template) detector as a Terraform resource.
    These are the unmodified source-of-truth detectors — no cmdb_id filter.
    The resource is tagged `golden` so it's easy to identify.
    """
    res  = slug(det["name"])
    name = det["name"]
    tags = sorted(set((det.get("tags") or []) + ["golden", "global-template"]))
    tags_tf = ", ".join(f'"{t}"' for t in tags)

    return f"""\
# Golden detector — source of truth, no team filter applied.
# Generated by scripts/generate.py from detector ID: {det['id']}
# DO NOT edit by hand. Re-run generate.py to sync changes from Splunk O11y.

resource "signalfx_detector" "golden_{res}" {{
  name        = "{tf_escape(name)}"
  description = "{tf_escape(det.get('description', ''))}"

  program_options {{
    minimum_resolution = {min_resolution(det)}
  }}

  program_text = <<-EOT
{det.get('programText', '').rstrip()}
  EOT

  tags = [{tags_tf}]

  {viz_tf(det)}
{rules_tf(det)}

  lifecycle {{
    # Golden detectors are the source of truth — protect from accidental deletion.
    prevent_destroy = true
  }}
}}
"""


# ---------------------------------------------------------------------------
# Team detector rendering  (terraform/teams/<team>/<detector_slug>.tf)
# ---------------------------------------------------------------------------

def render_team_detector_tf(det, team):
    """
    Render one detector file for a specific team, with cmdb_id filter injected.
    """
    team_name  = team["name"]
    team_id    = team["splunk_team_id"]
    cmdb_ids   = team["cmdb_ids"]
    det_id     = det["id"]
    res        = slug(det["name"])
    name       = f"{det['name']} [{team_name}]"
    program    = inject_filter(det.get("programText", ""), cmdb_ids)

    tags = sorted(
        set((det.get("tags") or []) + [f"team:{team_name}", f"golden:{det_id}", "team-scoped"])
        - {"global-template", "golden"}
    )
    tags_tf = ", ".join(f'"{t}"' for t in tags)

    return f"""\
# Team-scoped detector for: {team_name}
# cmdb_id(s): {', '.join(cmdb_ids)}
# Cloned from golden detector: {det_id}
# Generated by scripts/generate.py — do not edit by hand.

resource "signalfx_detector" "{team_name}_{res}" {{
  name        = "{tf_escape(name)}"
  description = "Scoped to {team_name} (cmdb_id: {', '.join(cmdb_ids)}). Golden: {det_id}"

  program_options {{
    minimum_resolution = {min_resolution(det)}
  }}

  program_text = <<-EOT
{program.rstrip()}
  EOT

  teams = ["{team_id}"]

  tags = [{tags_tf}]

  {viz_tf(det)}
{rules_tf(det)}

  lifecycle {{
    prevent_destroy = false
    ignore_changes  = [
      # Remove this block if you want Terraform to own notifications fully.
      # notifications
    ]
  }}
}}
"""


def render_team_main_tf(team, detectors):
    """
    Render terraform/teams/<team>/main.tf — team metadata comment block.
    No resources here; just documents what this directory owns.
    """
    det_names = "\n".join(f"#   - {d['name']}" for d in detectors)
    cmdb_list = "\n".join(f"#   - {c}" for c in team["cmdb_ids"])
    return f"""\
# =============================================================================
# Team: {team['name']}
# Splunk O11y Team ID: {team['splunk_team_id']}
#
# cmdb_ids owned by this team:
{cmdb_list}
#
# Detectors managed in this directory (one file per golden detector):
{det_names}
#
# To add a new detector: tag it 'global-template' in Splunk O11y, then re-run
#   python3 scripts/generate.py
# =============================================================================
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _update_main_tf_modules(main_tf_path, active_teams):
    """
    Idempotently insert/update module blocks for each active team in main.tf.
    Replaces the auto-generated section between marker comments.
    """
    marker_start = "# >>> AUTO-GENERATED TEAM MODULES — do not edit between markers <<<"
    marker_end   = "# >>> END AUTO-GENERATED TEAM MODULES <<<"

    module_blocks = "\n".join(
        f'module "team_{t["name"]}" {{\n'
        f'  source = "./teams/{t["name"]}"\n'
        f'}}'
        for t in active_teams
    )
    generated_section = f"{marker_start}\n{module_blocks}\n{marker_end}"

    if not main_tf_path.exists():
        return

    content = main_tf_path.read_text()

    if marker_start in content:
        # Replace existing section
        content = re.sub(
            re.escape(marker_start) + r".*?" + re.escape(marker_end),
            generated_section,
            content,
            flags=re.DOTALL,
        )
    else:
        # Append section
        content = content.rstrip() + f"\n\n{generated_section}\n"

    main_tf_path.write_text(content)
    print(f"  [updated] {main_tf_path}  (module blocks for {len(active_teams)} team(s))")


def render_team_provider_tf():
    """
    Each team subdirectory needs to declare the signalfx provider
    so Terraform knows to inherit it from the root module.
    """
    return """\
# Provider inheritance — do not edit.
# This file tells Terraform this module uses the signalfx provider
# configured in the root main.tf.
terraform {
  required_providers {
    signalfx = {
      source  = "splunk-terraform/signalfx"
      version = "~> 9.0"
    }
  }
}
"""


def write_or_print(path, content, dry_run, printed):
    if dry_run:
        if path not in printed:
            print(f"\n{'='*60}\n# {path}\n{'='*60}")
            print(content)
            printed.add(path)
    else:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content)


def main():
    parser = argparse.ArgumentParser(
        description="Generate organized Terraform from global Splunk O11y detectors"
    )
    parser.add_argument("--config",  default=str(REPO_ROOT / "team_config.yaml"))
    parser.add_argument("--out",     default=str(REPO_ROOT / "terraform"),
                        help="Root terraform directory (default: terraform/)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print to stdout instead of writing files")
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

    tf_root    = Path(args.out)
    golden_dir = tf_root / "golden"
    teams_dir  = tf_root / "teams"
    printed    = set()

    # Fetch global detectors
    print(f"\nFetching global template detectors from realm={REALM}...")
    detectors = fetch_global_detectors(config)
    if not detectors:
        print("\nNo global detectors found. Either:")
        print("  1. Tag template detectors with 'global-template' in Splunk O11y UI")
        print("  2. Add global_detector_ids to team_config.yaml")
        sys.exit(1)

    print(f"\n{len(detectors)} global detector(s) found.\n")

    # ── Write golden/ ────────────────────────────────────────────────────────
    print("Writing golden detectors...")
    for det in detectors:
        fname = f"{slug(det['name'])}.tf"
        path  = golden_dir / fname
        write_or_print(path, render_golden_tf(det), args.dry_run, printed)
        if not args.dry_run:
            print(f"  [golden]  {path}")

    # ── Write teams/<name>/ ──────────────────────────────────────────────────
    print("\nWriting team detectors...")
    skipped = []
    for team in teams:
        name = team["name"]
        if not team.get("cmdb_ids"):
            skipped.append(f"{name} (no cmdb_ids)")
            continue
        if team.get("splunk_team_id", "").startswith("REPLACE"):
            skipped.append(f"{name} (splunk_team_id placeholder not filled in)")
            continue

        team_dir = teams_dir / name

        # provider.tf — provider inheritance declaration
        write_or_print(
            team_dir / "provider.tf",
            render_team_provider_tf(),
            args.dry_run, printed,
        )

        # main.tf — team metadata comment block
        write_or_print(
            team_dir / "main.tf",
            render_team_main_tf(team, detectors),
            args.dry_run, printed,
        )

        # one .tf per golden detector
        for det in detectors:
            fname = f"{slug(det['name'])}.tf"
            write_or_print(
                team_dir / fname,
                render_team_detector_tf(det, team),
                args.dry_run, printed,
            )

        if not args.dry_run:
            print(f"  [team]    {team_dir}/  "
                  f"({len(detectors)} detector(s), cmdb_ids: {', '.join(team['cmdb_ids'])})")

    if skipped:
        print("\nSkipped teams:")
        for s in skipped:
            print(f"  [skip] {s}")

    # ── Update module blocks in terraform/main.tf ────────────────────────────
    active_teams = [
        t for t in teams
        if t.get("cmdb_ids") and not t.get("splunk_team_id", "").startswith("REPLACE")
    ]
    if not args.dry_run and active_teams:
        _update_main_tf_modules(tf_root / "main.tf", active_teams)

    if not args.dry_run:
        tree_teams = "\n".join(
            f"      ├── {t['name']}/  ({len(detectors)} detector(s))"
            for t in active_teams
        )
        print(f"""
Structure written to {tf_root}/:

  {tf_root}/
  ├── main.tf              ← updated with module blocks
  ├── variables.tf
  ├── golden/              ← {len(detectors)} golden detector(s)
  └── teams/
{tree_teams}

Next steps:
  cd {tf_root}
  terraform init
  terraform plan
  terraform apply
""")


if __name__ == "__main__":
    main()
