variable "dictionary_id" {
  description = "(required) - The dictionary the items belong to"
  type        = string
}

variable "items" {
  description = "(optional) - Map of key/value pairs that make up an item in the dictionary"
  type        = map(string)
  default     = null
}

variable "service_id" {
  description = "(required) - The service the dictionary belongs to"
  type        = string
}

