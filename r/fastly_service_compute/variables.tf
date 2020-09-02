variable "activate" {
  description = "(optional) - Conditionally prevents the Service from being activated"
  type        = bool
  default     = null
}

variable "comment" {
  description = "(optional) - A personal freeform descriptive note"
  type        = string
  default     = null
}

variable "force_destroy" {
  description = "(optional)"
  type        = bool
  default     = null
}

variable "name" {
  description = "(required) - Unique name for this Service"
  type        = string
}

variable "version_comment" {
  description = "(optional) - A personal freeform descriptive note"
  type        = string
  default     = null
}

variable "backend" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      address               = string
      auto_loadbalance      = bool
      between_bytes_timeout = number
      connect_timeout       = number
      error_threshold       = number
      first_byte_timeout    = number
      healthcheck           = string
      max_conn              = number
      max_tls_version       = string
      min_tls_version       = string
      name                  = string
      override_host         = string
      port                  = number
      shield                = string
      ssl_ca_cert           = string
      ssl_cert_hostname     = string
      ssl_check_cert        = bool
      ssl_ciphers           = string
      ssl_client_cert       = string
      ssl_client_key        = string
      ssl_hostname          = string
      ssl_sni_hostname      = string
      use_ssl               = bool
      weight                = number
    }
  ))
  default = []
}

variable "bigquerylogging" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      dataset    = string
      email      = string
      name       = string
      project_id = string
      secret_key = string
      table      = string
      template   = string
    }
  ))
  default = []
}

variable "blobstoragelogging" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      account_name     = string
      container        = string
      gzip_level       = number
      message_type     = string
      name             = string
      path             = string
      period           = number
      public_key       = string
      sas_token        = string
      timestamp_format = string
    }
  ))
  default = []
}

variable "domain" {
  description = "nested mode: NestingSet, min items: 1, max items: 0"
  type = set(object(
    {
      comment = string
      name    = string
    }
  ))
}

variable "gcslogging" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      bucket_name      = string
      email            = string
      gzip_level       = number
      message_type     = string
      name             = string
      path             = string
      period           = number
      secret_key       = string
      timestamp_format = string
    }
  ))
  default = []
}

variable "healthcheck" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      check_interval    = number
      expected_response = number
      host              = string
      http_version      = string
      initial           = number
      method            = string
      name              = string
      path              = string
      threshold         = number
      timeout           = number
      window            = number
    }
  ))
  default = []
}

variable "httpslogging" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      content_type        = string
      header_name         = string
      header_value        = string
      json_format         = string
      message_type        = string
      method              = string
      name                = string
      request_max_bytes   = number
      request_max_entries = number
      tls_ca_cert         = string
      tls_client_cert     = string
      tls_client_key      = string
      tls_hostname        = string
      url                 = string
    }
  ))
  default = []
}

variable "logentries" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      name    = string
      port    = number
      token   = string
      use_tls = bool
    }
  ))
  default = []
}

variable "logging_cloudfiles" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      access_key       = string
      bucket_name      = string
      gzip_level       = number
      message_type     = string
      name             = string
      path             = string
      period           = number
      public_key       = string
      region           = string
      timestamp_format = string
      user             = string
    }
  ))
  default = []
}

variable "logging_datadog" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      name   = string
      region = string
      token  = string
    }
  ))
  default = []
}

variable "logging_digitalocean" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      access_key       = string
      bucket_name      = string
      domain           = string
      gzip_level       = number
      message_type     = string
      name             = string
      path             = string
      period           = number
      public_key       = string
      secret_key       = string
      timestamp_format = string
    }
  ))
  default = []
}

variable "logging_elasticsearch" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      index               = string
      name                = string
      password            = string
      pipeline            = string
      request_max_bytes   = number
      request_max_entries = number
      tls_ca_cert         = string
      tls_client_cert     = string
      tls_client_key      = string
      tls_hostname        = string
      url                 = string
      user                = string
    }
  ))
  default = []
}

variable "logging_ftp" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      address          = string
      gzip_level       = number
      message_type     = string
      name             = string
      password         = string
      path             = string
      period           = number
      port             = number
      public_key       = string
      timestamp_format = string
      user             = string
    }
  ))
  default = []
}

variable "logging_googlepubsub" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      name       = string
      project_id = string
      secret_key = string
      topic      = string
      user       = string
    }
  ))
  default = []
}

variable "logging_heroku" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      name  = string
      token = string
      url   = string
    }
  ))
  default = []
}

variable "logging_honeycomb" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      dataset = string
      name    = string
      token   = string
    }
  ))
  default = []
}

variable "logging_kafka" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      brokers           = string
      compression_codec = string
      name              = string
      required_acks     = string
      tls_ca_cert       = string
      tls_client_cert   = string
      tls_client_key    = string
      tls_hostname      = string
      topic             = string
      use_tls           = bool
    }
  ))
  default = []
}

variable "logging_loggly" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      name  = string
      token = string
    }
  ))
  default = []
}

variable "logging_logshuttle" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      name  = string
      token = string
      url   = string
    }
  ))
  default = []
}

variable "logging_newrelic" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      name  = string
      token = string
    }
  ))
  default = []
}

variable "logging_openstack" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      access_key       = string
      bucket_name      = string
      gzip_level       = number
      message_type     = string
      name             = string
      path             = string
      period           = number
      public_key       = string
      timestamp_format = string
      url              = string
      user             = string
    }
  ))
  default = []
}

variable "logging_scalyr" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      name   = string
      region = string
      token  = string
    }
  ))
  default = []
}

variable "logging_sftp" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      address          = string
      gzip_level       = number
      message_type     = string
      name             = string
      password         = string
      path             = string
      period           = number
      port             = number
      public_key       = string
      secret_key       = string
      ssh_known_hosts  = string
      timestamp_format = string
      user             = string
    }
  ))
  default = []
}

variable "package" {
  description = "nested mode: NestingList, min items: 1, max items: 1"
  type = set(object(
    {
      filename         = string
      source_code_hash = string
    }
  ))
}

variable "papertrail" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      address = string
      name    = string
      port    = number
    }
  ))
  default = []
}

variable "s3logging" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      bucket_name                       = string
      domain                            = string
      gzip_level                        = number
      message_type                      = string
      name                              = string
      path                              = string
      period                            = number
      public_key                        = string
      redundancy                        = string
      s3_access_key                     = string
      s3_secret_key                     = string
      server_side_encryption            = string
      server_side_encryption_kms_key_id = string
      timestamp_format                  = string
    }
  ))
  default = []
}

variable "splunk" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      name         = string
      tls_ca_cert  = string
      tls_hostname = string
      token        = string
      url          = string
    }
  ))
  default = []
}

variable "sumologic" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      message_type = string
      name         = string
      url          = string
    }
  ))
  default = []
}

variable "syslog" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      address         = string
      message_type    = string
      name            = string
      port            = number
      tls_ca_cert     = string
      tls_client_cert = string
      tls_client_key  = string
      tls_hostname    = string
      token           = string
      use_tls         = bool
    }
  ))
  default = []
}

