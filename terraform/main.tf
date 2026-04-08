terraform {
  required_providers {
    signalfx = {
      source  = "splunk-terraform/signalfx"
      version = "~> 9.0"
    }
  }

  # Uncomment to store state remotely (recommended for teams)
  # backend "s3" {
  #   bucket = "your-tfstate-bucket"
  #   key    = "detector-automation/terraform.tfstate"
  #   region = "us-east-1"
  # }
}

provider "signalfx" {
  auth_token = var.splunk_access_token
  api_url    = "https://api.${var.splunk_realm}.signalfx.com"
}

# ---------------------------------------------------------------------------
# Golden detectors — source of truth, no team filter
# ---------------------------------------------------------------------------
# Generated files live in golden/. Terraform picks them up automatically
# because all .tf files in this directory share the same root module.

# ---------------------------------------------------------------------------
# Team detectors — one subdirectory per team, loaded as modules
# ---------------------------------------------------------------------------
# Each teams/<name>/ directory is a child module that inherits the provider.
# The generator writes teams/<name>/main.tf + one .tf per golden detector.
#
# Add a module block here for each team defined in team_config.yaml.
# Re-run scripts/generate.py to keep this file in sync.
#
# Example (uncomment and fill in after running generate.py):
#
# module "team_platform" {
#   source = "./teams/platform"
# }
#
# module "team_payments" {
#   source = "./teams/payments"
# }
