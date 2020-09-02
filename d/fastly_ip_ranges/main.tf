terraform {
  required_providers {
    fastly = ">= 0.19.1"
  }
}

data "fastly_ip_ranges" "this" {
}

