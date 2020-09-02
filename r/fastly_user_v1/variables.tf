variable "login" {
  description = "(required) - The email address, which is the login name, of this user."
  type        = string
}

variable "name" {
  description = "(required) - The real life name of the user."
  type        = string
}

variable "role" {
  description = "(optional) - The user-assigned permissions role. Can be `user` (the default), `billing`, `engineer`, or `superuser`."
  type        = string
  default     = null
}

