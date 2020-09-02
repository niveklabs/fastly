terraform {
  required_providers {
    fastly = ">= 0.19.1"
  }
}

resource "fastly_user_v1" "this" {
  login = var.login
  name  = var.name
  role  = var.role
}

