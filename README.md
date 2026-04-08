# detector-automation

Automated framework for cloning global Splunk Observability Cloud detectors per team,
pre-filtered to each team's `cmdb_id` values.

## How it works

```
Global Detector (no filter)
        │
        ▼
  generate.py  ──── team_config.yaml ──── discovers cmdb_id values from Dimension API
        │
        ▼
  terraform/          (generated, one .tf file per team)
  ├── main.tf         (provider config)
  ├── team_platform.tf
  ├── team_payments.tf
  └── ...
        │
        ▼
  terraform apply     (creates/updates team-scoped detectors in Splunk O11y)
```

## Architecture

| Component | Purpose |
|-----------|---------|
| `team_config.yaml` | Maps teams → cmdb_ids + Splunk team ID. Edit this to onboard new teams |
| `scripts/generate.py` | Reads config, fetches global detectors, renders Terraform for each team |
| `scripts/discover_cmdb_ids.py` | Helper: lists all cmdb_id values seen in your org via Dimension API |
| `terraform/main.tf` | Provider config (Splunk O11y + variables) |
| `terraform/team_*.tf` | Generated per-team detector resources (do not edit by hand) |

## Setup

### 1. Install dependencies

```bash
pip install requests pyyaml
terraform init terraform/
```

### 2. Discover cmdb_id values in your org

```bash
export SPLUNK_ACCESS_TOKEN=<your-token>
export SPLUNK_REALM=us1
python3 scripts/discover_cmdb_ids.py
```

### 3. Configure teams

Edit `team_config.yaml`:

```yaml
global_detector_tag: global-template   # tag applied to global detectors in Splunk O11y
                                        # OR use global_detector_ids list below

teams:
  - name: platform
    splunk_team_id: ABC123DEF           # Splunk O11y team ID (get from /v2/team or discover script)
    cmdb_ids:
      - APP-1001
      - APP-1002

  - name: payments
    splunk_team_id: GHI456JKL
    cmdb_ids:
      - APP-2001
```

### 4. Tag your global detectors

In Splunk O11y UI: open each global/template detector → Edit → add tag `global-template`.
Or set `global_detector_ids` in `team_config.yaml` to list them explicitly.

### 5. Generate Terraform

```bash
export SPLUNK_ACCESS_TOKEN=<your-token>
export SPLUNK_REALM=us1
python3 scripts/generate.py
```

This writes `terraform/team_<name>.tf` for each team.

### 6. Apply

```bash
cd terraform/
terraform init
terraform plan
terraform apply
```

## Day-2 operations

| Change | Action |
|--------|--------|
| New global detector added | Tag it `global-template`, re-run generate + apply |
| New team onboarded | Add to `team_config.yaml`, re-run generate + apply |
| New cmdb_id added to a team | Update `team_config.yaml`, re-run generate + apply |
| Global detector SignalFlow updated | Re-run generate + apply — Terraform updates in-place |

## SignalFlow filter injection

The generator injects `cmdb_id` filters into global detector SignalFlow automatically.

| Global SignalFlow pattern | Injected result |
|--------------------------|-----------------|
| `fn_detector()` | `fn_detector(filter_=filter('cmdb_id', 'APP-001', 'APP-002'))` |
| `fn_detector(filter_=filter('sf_environment', 'prod'))` | `fn_detector(filter_=filter('cmdb_id', ...) and filter('sf_environment', 'prod'))` |
| Raw `detect(when(...))` | Wraps data calls with `filter('cmdb_id', ...)` |

Multiple cmdb_ids for a team are OR'd within one filter call:
`filter('cmdb_id', 'APP-001', 'APP-002', 'APP-003')`

## File layout

```
detector-automation/
├── README.md
├── team_config.yaml          ← edit this
├── scripts/
│   ├── generate.py           ← main entrypoint
│   └── discover_cmdb_ids.py  ← run first to see cmdb_ids in your org
└── terraform/
    ├── main.tf               ← provider + backend config
    ├── variables.tf          ← input variables
    └── team_*.tf             ← generated (do not edit by hand)
```
