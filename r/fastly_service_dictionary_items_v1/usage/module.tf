module "fastly_service_dictionary_items_v1" {
  source = "./modules/fastly/r/fastly_service_dictionary_items_v1"

  # dictionary_id - (required) is a type of string
  dictionary_id = null
  # items - (optional) is a type of map of string
  items = {}
  # service_id - (required) is a type of string
  service_id = null
}
