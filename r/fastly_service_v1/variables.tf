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

variable "default_host" {
  description = "(optional) - The default hostname for the version"
  type        = string
  default     = null
}

variable "default_ttl" {
  description = "(optional) - The default Time-to-live (TTL) for the version"
  type        = number
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

variable "acl" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      acl_id = string
      name   = string
    }
  ))
  default = []
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
      request_condition     = string
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
      dataset            = string
      email              = string
      format             = string
      name               = string
      placement          = string
      project_id         = string
      response_condition = string
      secret_key         = string
      table              = string
      template           = string
    }
  ))
  default = []
}

variable "blobstoragelogging" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      account_name       = string
      container          = string
      format             = string
      format_version     = number
      gzip_level         = number
      message_type       = string
      name               = string
      path               = string
      period             = number
      placement          = string
      public_key         = string
      response_condition = string
      sas_token          = string
      timestamp_format   = string
    }
  ))
  default = []
}

variable "cache_setting" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      action          = string
      cache_condition = string
      name            = string
      stale_ttl       = number
      ttl             = number
    }
  ))
  default = []
}

variable "condition" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      name      = string
      priority  = number
      statement = string
      type      = string
    }
  ))
  default = []
}

variable "dictionary" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      dictionary_id = string
      name          = string
      write_only    = bool
    }
  ))
  default = []
}

variable "director" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      backends = set(string)
      capacity = number
      comment  = string
      name     = string
      quorum   = number
      retries  = number
      shield   = string
      type     = number
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

variable "dynamicsnippet" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      name       = string
      priority   = number
      snippet_id = string
      type       = string
    }
  ))
  default = []
}

variable "gcslogging" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      bucket_name        = string
      email              = string
      format             = string
      gzip_level         = number
      message_type       = string
      name               = string
      path               = string
      period             = number
      placement          = string
      response_condition = string
      secret_key         = string
      timestamp_format   = string
    }
  ))
  default = []
}

variable "gzip" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      cache_condition = string
      content_types   = set(string)
      extensions      = set(string)
      name            = string
    }
  ))
  default = []
}

variable "header" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      action             = string
      cache_condition    = string
      destination        = string
      ignore_if_set      = bool
      name               = string
      priority           = number
      regex              = string
      request_condition  = string
      response_condition = string
      source             = string
      substitution       = string
      type               = string
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
      format              = string
      format_version      = number
      header_name         = string
      header_value        = string
      json_format         = string
      message_type        = string
      method              = string
      name                = string
      placement           = string
      request_max_bytes   = number
      request_max_entries = number
      response_condition  = string
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
      format             = string
      format_version     = number
      name               = string
      placement          = string
      port               = number
      response_condition = string
      token              = string
      use_tls            = bool
    }
  ))
  default = []
}

variable "logging_cloudfiles" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      access_key         = string
      bucket_name        = string
      format             = string
      format_version     = number
      gzip_level         = number
      message_type       = string
      name               = string
      path               = string
      period             = number
      placement          = string
      public_key         = string
      region             = string
      response_condition = string
      timestamp_format   = string
      user               = string
    }
  ))
  default = []
}

variable "logging_datadog" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      format             = string
      format_version     = number
      name               = string
      placement          = string
      region             = string
      response_condition = string
      token              = string
    }
  ))
  default = []
}

variable "logging_digitalocean" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      access_key         = string
      bucket_name        = string
      domain             = string
      format             = string
      format_version     = number
      gzip_level         = number
      message_type       = string
      name               = string
      path               = string
      period             = number
      placement          = string
      public_key         = string
      response_condition = string
      secret_key         = string
      timestamp_format   = string
    }
  ))
  default = []
}

variable "logging_elasticsearch" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      format              = string
      format_version      = number
      index               = string
      name                = string
      password            = string
      pipeline            = string
      placement           = string
      request_max_bytes   = number
      request_max_entries = number
      response_condition  = string
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
      address            = string
      format             = string
      format_version     = number
      gzip_level         = number
      message_type       = string
      name               = string
      password           = string
      path               = string
      period             = number
      placement          = string
      port               = number
      public_key         = string
      response_condition = string
      timestamp_format   = string
      user               = string
    }
  ))
  default = []
}

variable "logging_googlepubsub" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      format             = string
      format_version     = number
      name               = string
      placement          = string
      project_id         = string
      response_condition = string
      secret_key         = string
      topic              = string
      user               = string
    }
  ))
  default = []
}

variable "logging_heroku" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      format             = string
      format_version     = number
      name               = string
      placement          = string
      response_condition = string
      token              = string
      url                = string
    }
  ))
  default = []
}

variable "logging_honeycomb" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      dataset            = string
      format             = string
      format_version     = number
      name               = string
      placement          = string
      response_condition = string
      token              = string
    }
  ))
  default = []
}

variable "logging_kafka" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      brokers            = string
      compression_codec  = string
      format             = string
      format_version     = number
      name               = string
      placement          = string
      required_acks      = string
      response_condition = string
      tls_ca_cert        = string
      tls_client_cert    = string
      tls_client_key     = string
      tls_hostname       = string
      topic              = string
      use_tls            = bool
    }
  ))
  default = []
}

variable "logging_loggly" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      format             = string
      format_version     = number
      name               = string
      placement          = string
      response_condition = string
      token              = string
    }
  ))
  default = []
}

variable "logging_logshuttle" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      format             = string
      format_version     = number
      name               = string
      placement          = string
      response_condition = string
      token              = string
      url                = string
    }
  ))
  default = []
}

variable "logging_newrelic" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      format             = string
      format_version     = number
      name               = string
      placement          = string
      response_condition = string
      token              = string
    }
  ))
  default = []
}

variable "logging_openstack" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      access_key         = string
      bucket_name        = string
      format             = string
      format_version     = number
      gzip_level         = number
      message_type       = string
      name               = string
      path               = string
      period             = number
      placement          = string
      public_key         = string
      response_condition = string
      timestamp_format   = string
      url                = string
      user               = string
    }
  ))
  default = []
}

variable "logging_scalyr" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      format             = string
      format_version     = number
      name               = string
      placement          = string
      region             = string
      response_condition = string
      token              = string
    }
  ))
  default = []
}

variable "logging_sftp" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      address            = string
      format             = string
      format_version     = number
      gzip_level         = number
      message_type       = string
      name               = string
      password           = string
      path               = string
      period             = number
      placement          = string
      port               = number
      public_key         = string
      response_condition = string
      secret_key         = string
      ssh_known_hosts    = string
      timestamp_format   = string
      user               = string
    }
  ))
  default = []
}

variable "papertrail" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      address            = string
      format             = string
      name               = string
      placement          = string
      port               = number
      response_condition = string
    }
  ))
  default = []
}

variable "request_setting" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      action            = string
      bypass_busy_wait  = bool
      default_host      = string
      force_miss        = bool
      force_ssl         = bool
      geo_headers       = bool
      hash_keys         = string
      max_stale_age     = number
      name              = string
      request_condition = string
      timer_support     = bool
      xff               = string
    }
  ))
  default = []
}

variable "response_object" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      cache_condition   = string
      content           = string
      content_type      = string
      name              = string
      request_condition = string
      response          = string
      status            = number
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
      format                            = string
      format_version                    = number
      gzip_level                        = number
      message_type                      = string
      name                              = string
      path                              = string
      period                            = number
      placement                         = string
      public_key                        = string
      redundancy                        = string
      response_condition                = string
      s3_access_key                     = string
      s3_secret_key                     = string
      server_side_encryption            = string
      server_side_encryption_kms_key_id = string
      timestamp_format                  = string
    }
  ))
  default = []
}

variable "snippet" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      content  = string
      name     = string
      priority = number
      type     = string
    }
  ))
  default = []
}

variable "splunk" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      format             = string
      format_version     = number
      name               = string
      placement          = string
      response_condition = string
      tls_ca_cert        = string
      tls_hostname       = string
      token              = string
      url                = string
    }
  ))
  default = []
}

variable "sumologic" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      format             = string
      format_version     = number
      message_type       = string
      name               = string
      placement          = string
      response_condition = string
      url                = string
    }
  ))
  default = []
}

variable "syslog" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      address            = string
      format             = string
      format_version     = number
      message_type       = string
      name               = string
      placement          = string
      port               = number
      response_condition = string
      tls_ca_cert        = string
      tls_client_cert    = string
      tls_client_key     = string
      tls_hostname       = string
      token              = string
      use_tls            = bool
    }
  ))
  default = []
}

variable "vcl" {
  description = "nested mode: NestingSet, min items: 0, max items: 0"
  type = set(object(
    {
      content = string
      main    = bool
      name    = string
    }
  ))
  default = []
}

