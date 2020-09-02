variable "acl_id" {
  description = "(required) - ACL Id"
  type        = string
}

variable "service_id" {
  description = "(required) - Service Id"
  type        = string
}

variable "entry" {
  description = "nested mode: NestingSet, min items: 0, max items: 10000"
  type = set(object(
    {
      comment = string
      id      = string
      ip      = string
      negated = bool
      subnet  = string
    }
  ))
  default = []
}

