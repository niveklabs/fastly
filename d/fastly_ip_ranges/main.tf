terraform {
  required_providers {
    fastly = ">= 0.19.2"
  }
}

data "fastly_ip_ranges" "this" {
}

