module "fastly_service_dynamic_snippet_content_v1" {
  source = "./modules/fastly/r/fastly_service_dynamic_snippet_content_v1"

  # content - (required) is a type of string
  content = null
  # service_id - (required) is a type of string
  service_id = null
  # snippet_id - (required) is a type of string
  snippet_id = null
}
