# detector-automation

Automated framework for cloning global Splunk Observability Cloud detectors per team,
pre-filtered to each team's `cmdb_id` values, with team-owned customizations via `overrides.yaml`.

## How it works

```
Global Detector (no filter)
        │
        ▼
  generate.py  ──── team_config.yaml
        │
        ├── terraform/golden/              ← one .tf per global detector (source of truth)
        │
        └── terraform/teams/<name>/        ← per-team directory
            ├── main.tf                    ← team header + comments
            ├── provider.tf                ← provider inheritance
            ├── overrides.yaml             ← team-owned customizations (edit freely)
            └── <detector>.tf              ← generated, cmdb_id-filtered clone
        │
        ▼
  terraform apply     (creates/updates team-scoped detectors in Splunk O11y)
```

## Architecture

| Component | Purpose |
|-----------|---------|
| `team_config.yaml` | Maps teams to cmdb_ids + Splunk team ID |
| `scripts/generate.py` | Fetches global detectors, renders Terraform per team |
| `scripts/discover_cmdb_ids.py` | Discovers cmdb_id values, teams, and global detectors in your org |
| `terraform/main.tf` | Root provider config + auto-updated module blocks |
| `terraform/golden/` | Golden detector definitions (prevent_destroy = true) |
| `terraform/teams/<name>/` | Per-team detector clones with cmdb_id filter injected |

---

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

python3 scripts/discover_cmdb_ids.py --all
```

This runs three queries:

| Flag | What it shows |
|------|--------------|
| `--cmdb-ids` | All `cmdb_id` values seen in your org via the Dimension API |
| `--teams` | All Splunk O11y teams with their IDs — copy these into `team_config.yaml` |
| `--detectors` | Detectors tagged `global-template` — confirms your golden detectors are discoverable |

#### How cmdb_id discovery works

`discover_cmdb_ids.py` queries the Splunk Observability Dimension API:

```
GET /v2/dimension?query=key:cmdb_id&limit=10000
```

This returns every unique `cmdb_id` value that has been reported as a span resource attribute
or metric dimension in your org. For each value it also shows which services and environments
it appears in, so you can map them to the right team.

> **No cmdb_ids found?** Services must be instrumented to emit `cmdb_id` as a resource attribute.
>
> Via OTel SDK (Java):
> ```java
> Resource.builder().put("cmdb_id", "APP-1001").build()
> ```
>
> Via OTel Collector resource processor:
> ```yaml
> processors:
>   resource:
>     attributes:
>       - action: insert
>         key: cmdb_id
>         value: APP-1001
> ```

### 3. Configure teams

Edit `team_config.yaml`:

```yaml
global_detector_tag: global-template   # tag applied to global detectors in Splunk O11y
# global_detector_ids:                 # OR list detector IDs explicitly
#   - AbCdEfGhIjK

realm: us1

teams:
  - name: platform
    splunk_team_id: ABC123DEF           # from: python3 scripts/discover_cmdb_ids.py --teams
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

Or skip tagging and list IDs explicitly in `team_config.yaml`:
```yaml
global_detector_ids:
  - AbCdEfGhIjK
  - LmNoPqRsTuV
```

### 5. Generate Terraform

```bash
python3 scripts/generate.py
```

Optional flags:

| Flag | Description |
|------|-------------|
| `--dry-run` | Print what would be written without touching any files |
| `--diff` | Compare on-disk TF vs what would be generated (see below) |
| `--team <name>` | Scope `--diff` to a single team |
| `--config <path>` | Use a different config file (default: `team_config.yaml`) |
| `--out <path>` | Write to a different output directory (default: `terraform/`) |

### 6. Apply

```bash
cd terraform/
terraform init
terraform plan
terraform apply
```

---

## Day-2 operations

| Change | Action |
|--------|--------|
| New global detector added | Tag it `global-template`, re-run `generate.py` + `terraform apply` |
| New team onboarded | Add to `team_config.yaml`, re-run `generate.py` + `terraform apply` |
| New cmdb_id for a team | Update `team_config.yaml`, re-run `generate.py` + `terraform apply` |
| Global detector updated | Re-run `generate.py --diff` to preview, then `generate.py` + `terraform apply` |
| Team wants to customize | Edit `terraform/teams/<name>/overrides.yaml`, re-run `generate.py` |

---

## Team customizations (overrides.yaml)

Each team directory contains an `overrides.yaml` generated on first run. Teams can edit this
freely — it is **never overwritten** by `generate.py`.

```yaml
detectors:
  apm_sudden_change_in_service_latency:
    # Disable this detector entirely for this team
    disabled: false

    # Override the detector description
    description: "Platform team: latency alerts for APP-1001/APP-1002"

    # Add extra SignalFlow filters (AND'd with the cmdb_id filter)
    extra_filters:
      - key: sf_environment
        value: production

    # Add extra tags to the Terraform resource
    tags:
      - platform-critical

    # Per-rule overrides
    rules:
      - detect_label: "APM - Sudden change in service latency"
        severity: Warning          # override Critical -> Warning
        disabled: false
        notifications:
          - type: PagerDuty
            credentialId: abc123
```

### Supported override fields

| Field | Scope | Description |
|-------|-------|-------------|
| `disabled` | detector | Skip generating this detector for the team |
| `description` | detector | Replace the detector description |
| `extra_filters` | detector | Extra `filter(key, value)` AND'd into SignalFlow |
| `tags` | detector | Additional tags appended to the resource |
| `rules[].severity` | rule | Override alert severity (Critical/Major/Minor/Warning/Info) |
| `rules[].notifications` | rule | Replace notification destinations |
| `rules[].disabled` | rule | Disable a specific alert rule |

---

## Diffing golden changes vs team overrides

When a global detector is updated in Splunk O11y, run `--diff` to see what would change and
whether any changes conflict with active overrides:

```bash
python3 scripts/generate.py --diff
```

Example output:
```
----------------------------------------------------------------------
Team: platform  (APP-1001, APP-1002)

  ~ APM - Sudden change in service latency  [apm_sudden_change_in_service_latency.tf]
    Overrides active: description, rule 'APM - Sudden change in service latency': severity=Warning
    --- current/apm_sudden_change_in_service_latency.tf
    +++ generated/apm_sudden_change_in_service_latency.tf
    @@ -5,7 +5,7 @@
     resource "signalfx_detector" "platform_apm_..." {
    -  description = "Old description"        <- override active
    +  description = "Platform team: ..."     <- from override
    -    severity     = "Critical"            <- override active
    +    severity     = "Warning"             <- from override
```

Lines marked `<- override active` are intentional team customizations — safe to ignore.
Lines without annotation are upstream golden changes that will be applied.

---

## SignalFlow filter injection

`generate.py` injects `cmdb_id` filters into global detector SignalFlow automatically.

| Global SignalFlow pattern | Injected result |
|--------------------------|-----------------|
| `fn_detector()` | `fn_detector(filter_=filter('cmdb_id', 'APP-001', 'APP-002'))` |
| `fn_detector(filter_=filter('sf_environment', 'prod'))` | `fn_detector(filter_=filter('cmdb_id', ...) and filter('sf_environment', 'prod'))` |
| Raw `data("metric", filter=...)` | `data("metric", filter=filter('cmdb_id', ...) and ...)` |

Multiple cmdb_ids for a team are OR'd within one filter call:
```
filter('cmdb_id', 'APP-001', 'APP-002', 'APP-003')
```

`extra_filters` from `overrides.yaml` are AND'd on top:
```
filter('cmdb_id', 'APP-001') and filter('sf_environment', 'production')
```

---

## File layout

```
detector-automation/
├── README.md
├── team_config.yaml              <- edit this to onboard teams
├── scripts/
│   ├── generate.py               <- main entrypoint
│   └── discover_cmdb_ids.py      <- run first to discover cmdb_ids and teams
└── terraform/
    ├── main.tf                   <- provider config + auto-updated module blocks
    ├── variables.tf              <- splunk_access_token, splunk_realm
    ├── terraform.tfvars.example  <- copy to terraform.tfvars and fill in
    ├── golden/                   <- golden detector definitions (do not edit)
    │   └── <detector>.tf
    └── teams/
        └── <team-name>/
            ├── provider.tf       <- provider inheritance (do not edit)
            ├── main.tf           <- team header (do not edit)
            ├── overrides.yaml    <- team customizations (edit freely)
            └── <detector>.tf     <- generated clone (do not edit)
```
