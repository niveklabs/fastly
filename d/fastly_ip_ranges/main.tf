terraform {
  required_providers {
    fastly = ">= 0.19.0"
  }
}

data "fastly_ip_ranges" "this" {
}

