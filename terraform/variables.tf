variable "splunk_access_token" {
  description = "Splunk Observability Cloud API access token"
  type        = string
  sensitive   = true
}

variable "splunk_realm" {
  description = "Splunk Observability Cloud realm (e.g. us1, us2, eu0, ap0)"
  type        = string
  default     = "us1"
}
