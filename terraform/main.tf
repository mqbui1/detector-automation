terraform {
  required_providers {
    signalfx = {
      source  = "splunk-terraform/signalfx"
      version = "~> 9.0"
    }
  }

  # Uncomment and configure for remote state (recommended for teams)
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
