terraform {
  required_providers {
    fastly = ">= 0.19.3"
  }
}

data "fastly_ip_ranges" "this" {
}

