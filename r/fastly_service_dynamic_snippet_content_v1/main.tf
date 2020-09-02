terraform {
  required_providers {
    fastly = ">= 0.19.1"
  }
}

resource "fastly_service_dynamic_snippet_content_v1" "this" {
  content    = var.content
  service_id = var.service_id
  snippet_id = var.snippet_id
}

