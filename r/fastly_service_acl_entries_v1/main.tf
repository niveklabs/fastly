terraform {
  required_providers {
    fastly = ">= 0.19.2"
  }
}

resource "fastly_service_acl_entries_v1" "this" {
  acl_id     = var.acl_id
  service_id = var.service_id

  dynamic "entry" {
    for_each = var.entry
    content {
      comment = entry.value["comment"]
      ip      = entry.value["ip"]
      negated = entry.value["negated"]
      subnet  = entry.value["subnet"]
    }
  }

}

