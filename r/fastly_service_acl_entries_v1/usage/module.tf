module "fastly_service_acl_entries_v1" {
  source = "./modules/fastly/r/fastly_service_acl_entries_v1"

  # acl_id - (required) is a type of string
  acl_id = null
  # service_id - (required) is a type of string
  service_id = null

  entry = [{
    comment = null
    id      = null
    ip      = null
    negated = null
    subnet  = null
  }]
}
