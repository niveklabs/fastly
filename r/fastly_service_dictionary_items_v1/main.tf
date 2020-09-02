terraform {
  required_providers {
    fastly = ">= 0.19.1"
  }
}

resource "fastly_service_dictionary_items_v1" "this" {
  dictionary_id = var.dictionary_id
  items         = var.items
  service_id    = var.service_id
}

