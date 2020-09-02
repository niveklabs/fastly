terraform {
  required_providers {
    fastly = ">= 0.19.1"
  }
}

resource "fastly_service_v1" "this" {
  activate        = var.activate
  comment         = var.comment
  default_host    = var.default_host
  default_ttl     = var.default_ttl
  force_destroy   = var.force_destroy
  name            = var.name
  version_comment = var.version_comment

  dynamic "acl" {
    for_each = var.acl
    content {
      name = acl.value["name"]
    }
  }

  dynamic "backend" {
    for_each = var.backend
    content {
      address               = backend.value["address"]
      auto_loadbalance      = backend.value["auto_loadbalance"]
      between_bytes_timeout = backend.value["between_bytes_timeout"]
      connect_timeout       = backend.value["connect_timeout"]
      error_threshold       = backend.value["error_threshold"]
      first_byte_timeout    = backend.value["first_byte_timeout"]
      healthcheck           = backend.value["healthcheck"]
      max_conn              = backend.value["max_conn"]
      max_tls_version       = backend.value["max_tls_version"]
      min_tls_version       = backend.value["min_tls_version"]
      name                  = backend.value["name"]
      override_host         = backend.value["override_host"]
      port                  = backend.value["port"]
      request_condition     = backend.value["request_condition"]
      shield                = backend.value["shield"]
      ssl_ca_cert           = backend.value["ssl_ca_cert"]
      ssl_cert_hostname     = backend.value["ssl_cert_hostname"]
      ssl_check_cert        = backend.value["ssl_check_cert"]
      ssl_ciphers           = backend.value["ssl_ciphers"]
      ssl_client_cert       = backend.value["ssl_client_cert"]
      ssl_client_key        = backend.value["ssl_client_key"]
      ssl_hostname          = backend.value["ssl_hostname"]
      ssl_sni_hostname      = backend.value["ssl_sni_hostname"]
      use_ssl               = backend.value["use_ssl"]
      weight                = backend.value["weight"]
    }
  }

  dynamic "bigquerylogging" {
    for_each = var.bigquerylogging
    content {
      dataset            = bigquerylogging.value["dataset"]
      email              = bigquerylogging.value["email"]
      format             = bigquerylogging.value["format"]
      name               = bigquerylogging.value["name"]
      placement          = bigquerylogging.value["placement"]
      project_id         = bigquerylogging.value["project_id"]
      response_condition = bigquerylogging.value["response_condition"]
      secret_key         = bigquerylogging.value["secret_key"]
      table              = bigquerylogging.value["table"]
      template           = bigquerylogging.value["template"]
    }
  }

  dynamic "blobstoragelogging" {
    for_each = var.blobstoragelogging
    content {
      account_name       = blobstoragelogging.value["account_name"]
      container          = blobstoragelogging.value["container"]
      format             = blobstoragelogging.value["format"]
      format_version     = blobstoragelogging.value["format_version"]
      gzip_level         = blobstoragelogging.value["gzip_level"]
      message_type       = blobstoragelogging.value["message_type"]
      name               = blobstoragelogging.value["name"]
      path               = blobstoragelogging.value["path"]
      period             = blobstoragelogging.value["period"]
      placement          = blobstoragelogging.value["placement"]
      public_key         = blobstoragelogging.value["public_key"]
      response_condition = blobstoragelogging.value["response_condition"]
      sas_token          = blobstoragelogging.value["sas_token"]
      timestamp_format   = blobstoragelogging.value["timestamp_format"]
    }
  }

  dynamic "cache_setting" {
    for_each = var.cache_setting
    content {
      action          = cache_setting.value["action"]
      cache_condition = cache_setting.value["cache_condition"]
      name            = cache_setting.value["name"]
      stale_ttl       = cache_setting.value["stale_ttl"]
      ttl             = cache_setting.value["ttl"]
    }
  }

  dynamic "condition" {
    for_each = var.condition
    content {
      name      = condition.value["name"]
      priority  = condition.value["priority"]
      statement = condition.value["statement"]
      type      = condition.value["type"]
    }
  }

  dynamic "dictionary" {
    for_each = var.dictionary
    content {
      name       = dictionary.value["name"]
      write_only = dictionary.value["write_only"]
    }
  }

  dynamic "director" {
    for_each = var.director
    content {
      backends = director.value["backends"]
      capacity = director.value["capacity"]
      comment  = director.value["comment"]
      name     = director.value["name"]
      quorum   = director.value["quorum"]
      retries  = director.value["retries"]
      shield   = director.value["shield"]
      type     = director.value["type"]
    }
  }

  dynamic "domain" {
    for_each = var.domain
    content {
      comment = domain.value["comment"]
      name    = domain.value["name"]
    }
  }

  dynamic "dynamicsnippet" {
    for_each = var.dynamicsnippet
    content {
      name     = dynamicsnippet.value["name"]
      priority = dynamicsnippet.value["priority"]
      type     = dynamicsnippet.value["type"]
    }
  }

  dynamic "gcslogging" {
    for_each = var.gcslogging
    content {
      bucket_name        = gcslogging.value["bucket_name"]
      email              = gcslogging.value["email"]
      format             = gcslogging.value["format"]
      gzip_level         = gcslogging.value["gzip_level"]
      message_type       = gcslogging.value["message_type"]
      name               = gcslogging.value["name"]
      path               = gcslogging.value["path"]
      period             = gcslogging.value["period"]
      placement          = gcslogging.value["placement"]
      response_condition = gcslogging.value["response_condition"]
      secret_key         = gcslogging.value["secret_key"]
      timestamp_format   = gcslogging.value["timestamp_format"]
    }
  }

  dynamic "gzip" {
    for_each = var.gzip
    content {
      cache_condition = gzip.value["cache_condition"]
      content_types   = gzip.value["content_types"]
      extensions      = gzip.value["extensions"]
      name            = gzip.value["name"]
    }
  }

  dynamic "header" {
    for_each = var.header
    content {
      action             = header.value["action"]
      cache_condition    = header.value["cache_condition"]
      destination        = header.value["destination"]
      ignore_if_set      = header.value["ignore_if_set"]
      name               = header.value["name"]
      priority           = header.value["priority"]
      regex              = header.value["regex"]
      request_condition  = header.value["request_condition"]
      response_condition = header.value["response_condition"]
      source             = header.value["source"]
      substitution       = header.value["substitution"]
      type               = header.value["type"]
    }
  }

  dynamic "healthcheck" {
    for_each = var.healthcheck
    content {
      check_interval    = healthcheck.value["check_interval"]
      expected_response = healthcheck.value["expected_response"]
      host              = healthcheck.value["host"]
      http_version      = healthcheck.value["http_version"]
      initial           = healthcheck.value["initial"]
      method            = healthcheck.value["method"]
      name              = healthcheck.value["name"]
      path              = healthcheck.value["path"]
      threshold         = healthcheck.value["threshold"]
      timeout           = healthcheck.value["timeout"]
      window            = healthcheck.value["window"]
    }
  }

  dynamic "httpslogging" {
    for_each = var.httpslogging
    content {
      content_type        = httpslogging.value["content_type"]
      format              = httpslogging.value["format"]
      format_version      = httpslogging.value["format_version"]
      header_name         = httpslogging.value["header_name"]
      header_value        = httpslogging.value["header_value"]
      json_format         = httpslogging.value["json_format"]
      message_type        = httpslogging.value["message_type"]
      method              = httpslogging.value["method"]
      name                = httpslogging.value["name"]
      placement           = httpslogging.value["placement"]
      request_max_bytes   = httpslogging.value["request_max_bytes"]
      request_max_entries = httpslogging.value["request_max_entries"]
      response_condition  = httpslogging.value["response_condition"]
      tls_ca_cert         = httpslogging.value["tls_ca_cert"]
      tls_client_cert     = httpslogging.value["tls_client_cert"]
      tls_client_key      = httpslogging.value["tls_client_key"]
      tls_hostname        = httpslogging.value["tls_hostname"]
      url                 = httpslogging.value["url"]
    }
  }

  dynamic "logentries" {
    for_each = var.logentries
    content {
      format             = logentries.value["format"]
      format_version     = logentries.value["format_version"]
      name               = logentries.value["name"]
      placement          = logentries.value["placement"]
      port               = logentries.value["port"]
      response_condition = logentries.value["response_condition"]
      token              = logentries.value["token"]
      use_tls            = logentries.value["use_tls"]
    }
  }

  dynamic "logging_cloudfiles" {
    for_each = var.logging_cloudfiles
    content {
      access_key         = logging_cloudfiles.value["access_key"]
      bucket_name        = logging_cloudfiles.value["bucket_name"]
      format             = logging_cloudfiles.value["format"]
      format_version     = logging_cloudfiles.value["format_version"]
      gzip_level         = logging_cloudfiles.value["gzip_level"]
      message_type       = logging_cloudfiles.value["message_type"]
      name               = logging_cloudfiles.value["name"]
      path               = logging_cloudfiles.value["path"]
      period             = logging_cloudfiles.value["period"]
      placement          = logging_cloudfiles.value["placement"]
      public_key         = logging_cloudfiles.value["public_key"]
      region             = logging_cloudfiles.value["region"]
      response_condition = logging_cloudfiles.value["response_condition"]
      timestamp_format   = logging_cloudfiles.value["timestamp_format"]
      user               = logging_cloudfiles.value["user"]
    }
  }

  dynamic "logging_datadog" {
    for_each = var.logging_datadog
    content {
      format             = logging_datadog.value["format"]
      format_version     = logging_datadog.value["format_version"]
      name               = logging_datadog.value["name"]
      placement          = logging_datadog.value["placement"]
      region             = logging_datadog.value["region"]
      response_condition = logging_datadog.value["response_condition"]
      token              = logging_datadog.value["token"]
    }
  }

  dynamic "logging_digitalocean" {
    for_each = var.logging_digitalocean
    content {
      access_key         = logging_digitalocean.value["access_key"]
      bucket_name        = logging_digitalocean.value["bucket_name"]
      domain             = logging_digitalocean.value["domain"]
      format             = logging_digitalocean.value["format"]
      format_version     = logging_digitalocean.value["format_version"]
      gzip_level         = logging_digitalocean.value["gzip_level"]
      message_type       = logging_digitalocean.value["message_type"]
      name               = logging_digitalocean.value["name"]
      path               = logging_digitalocean.value["path"]
      period             = logging_digitalocean.value["period"]
      placement          = logging_digitalocean.value["placement"]
      public_key         = logging_digitalocean.value["public_key"]
      response_condition = logging_digitalocean.value["response_condition"]
      secret_key         = logging_digitalocean.value["secret_key"]
      timestamp_format   = logging_digitalocean.value["timestamp_format"]
    }
  }

  dynamic "logging_elasticsearch" {
    for_each = var.logging_elasticsearch
    content {
      format              = logging_elasticsearch.value["format"]
      format_version      = logging_elasticsearch.value["format_version"]
      index               = logging_elasticsearch.value["index"]
      name                = logging_elasticsearch.value["name"]
      password            = logging_elasticsearch.value["password"]
      pipeline            = logging_elasticsearch.value["pipeline"]
      placement           = logging_elasticsearch.value["placement"]
      request_max_bytes   = logging_elasticsearch.value["request_max_bytes"]
      request_max_entries = logging_elasticsearch.value["request_max_entries"]
      response_condition  = logging_elasticsearch.value["response_condition"]
      tls_ca_cert         = logging_elasticsearch.value["tls_ca_cert"]
      tls_client_cert     = logging_elasticsearch.value["tls_client_cert"]
      tls_client_key      = logging_elasticsearch.value["tls_client_key"]
      tls_hostname        = logging_elasticsearch.value["tls_hostname"]
      url                 = logging_elasticsearch.value["url"]
      user                = logging_elasticsearch.value["user"]
    }
  }

  dynamic "logging_ftp" {
    for_each = var.logging_ftp
    content {
      address            = logging_ftp.value["address"]
      format             = logging_ftp.value["format"]
      format_version     = logging_ftp.value["format_version"]
      gzip_level         = logging_ftp.value["gzip_level"]
      message_type       = logging_ftp.value["message_type"]
      name               = logging_ftp.value["name"]
      password           = logging_ftp.value["password"]
      path               = logging_ftp.value["path"]
      period             = logging_ftp.value["period"]
      placement          = logging_ftp.value["placement"]
      port               = logging_ftp.value["port"]
      public_key         = logging_ftp.value["public_key"]
      response_condition = logging_ftp.value["response_condition"]
      timestamp_format   = logging_ftp.value["timestamp_format"]
      user               = logging_ftp.value["user"]
    }
  }

  dynamic "logging_googlepubsub" {
    for_each = var.logging_googlepubsub
    content {
      format             = logging_googlepubsub.value["format"]
      format_version     = logging_googlepubsub.value["format_version"]
      name               = logging_googlepubsub.value["name"]
      placement          = logging_googlepubsub.value["placement"]
      project_id         = logging_googlepubsub.value["project_id"]
      response_condition = logging_googlepubsub.value["response_condition"]
      secret_key         = logging_googlepubsub.value["secret_key"]
      topic              = logging_googlepubsub.value["topic"]
      user               = logging_googlepubsub.value["user"]
    }
  }

  dynamic "logging_heroku" {
    for_each = var.logging_heroku
    content {
      format             = logging_heroku.value["format"]
      format_version     = logging_heroku.value["format_version"]
      name               = logging_heroku.value["name"]
      placement          = logging_heroku.value["placement"]
      response_condition = logging_heroku.value["response_condition"]
      token              = logging_heroku.value["token"]
      url                = logging_heroku.value["url"]
    }
  }

  dynamic "logging_honeycomb" {
    for_each = var.logging_honeycomb
    content {
      dataset            = logging_honeycomb.value["dataset"]
      format             = logging_honeycomb.value["format"]
      format_version     = logging_honeycomb.value["format_version"]
      name               = logging_honeycomb.value["name"]
      placement          = logging_honeycomb.value["placement"]
      response_condition = logging_honeycomb.value["response_condition"]
      token              = logging_honeycomb.value["token"]
    }
  }

  dynamic "logging_kafka" {
    for_each = var.logging_kafka
    content {
      brokers            = logging_kafka.value["brokers"]
      compression_codec  = logging_kafka.value["compression_codec"]
      format             = logging_kafka.value["format"]
      format_version     = logging_kafka.value["format_version"]
      name               = logging_kafka.value["name"]
      placement          = logging_kafka.value["placement"]
      required_acks      = logging_kafka.value["required_acks"]
      response_condition = logging_kafka.value["response_condition"]
      tls_ca_cert        = logging_kafka.value["tls_ca_cert"]
      tls_client_cert    = logging_kafka.value["tls_client_cert"]
      tls_client_key     = logging_kafka.value["tls_client_key"]
      tls_hostname       = logging_kafka.value["tls_hostname"]
      topic              = logging_kafka.value["topic"]
      use_tls            = logging_kafka.value["use_tls"]
    }
  }

  dynamic "logging_loggly" {
    for_each = var.logging_loggly
    content {
      format             = logging_loggly.value["format"]
      format_version     = logging_loggly.value["format_version"]
      name               = logging_loggly.value["name"]
      placement          = logging_loggly.value["placement"]
      response_condition = logging_loggly.value["response_condition"]
      token              = logging_loggly.value["token"]
    }
  }

  dynamic "logging_logshuttle" {
    for_each = var.logging_logshuttle
    content {
      format             = logging_logshuttle.value["format"]
      format_version     = logging_logshuttle.value["format_version"]
      name               = logging_logshuttle.value["name"]
      placement          = logging_logshuttle.value["placement"]
      response_condition = logging_logshuttle.value["response_condition"]
      token              = logging_logshuttle.value["token"]
      url                = logging_logshuttle.value["url"]
    }
  }

  dynamic "logging_newrelic" {
    for_each = var.logging_newrelic
    content {
      format             = logging_newrelic.value["format"]
      format_version     = logging_newrelic.value["format_version"]
      name               = logging_newrelic.value["name"]
      placement          = logging_newrelic.value["placement"]
      response_condition = logging_newrelic.value["response_condition"]
      token              = logging_newrelic.value["token"]
    }
  }

  dynamic "logging_openstack" {
    for_each = var.logging_openstack
    content {
      access_key         = logging_openstack.value["access_key"]
      bucket_name        = logging_openstack.value["bucket_name"]
      format             = logging_openstack.value["format"]
      format_version     = logging_openstack.value["format_version"]
      gzip_level         = logging_openstack.value["gzip_level"]
      message_type       = logging_openstack.value["message_type"]
      name               = logging_openstack.value["name"]
      path               = logging_openstack.value["path"]
      period             = logging_openstack.value["period"]
      placement          = logging_openstack.value["placement"]
      public_key         = logging_openstack.value["public_key"]
      response_condition = logging_openstack.value["response_condition"]
      timestamp_format   = logging_openstack.value["timestamp_format"]
      url                = logging_openstack.value["url"]
      user               = logging_openstack.value["user"]
    }
  }

  dynamic "logging_scalyr" {
    for_each = var.logging_scalyr
    content {
      format             = logging_scalyr.value["format"]
      format_version     = logging_scalyr.value["format_version"]
      name               = logging_scalyr.value["name"]
      placement          = logging_scalyr.value["placement"]
      region             = logging_scalyr.value["region"]
      response_condition = logging_scalyr.value["response_condition"]
      token              = logging_scalyr.value["token"]
    }
  }

  dynamic "logging_sftp" {
    for_each = var.logging_sftp
    content {
      address            = logging_sftp.value["address"]
      format             = logging_sftp.value["format"]
      format_version     = logging_sftp.value["format_version"]
      gzip_level         = logging_sftp.value["gzip_level"]
      message_type       = logging_sftp.value["message_type"]
      name               = logging_sftp.value["name"]
      password           = logging_sftp.value["password"]
      path               = logging_sftp.value["path"]
      period             = logging_sftp.value["period"]
      placement          = logging_sftp.value["placement"]
      port               = logging_sftp.value["port"]
      public_key         = logging_sftp.value["public_key"]
      response_condition = logging_sftp.value["response_condition"]
      secret_key         = logging_sftp.value["secret_key"]
      ssh_known_hosts    = logging_sftp.value["ssh_known_hosts"]
      timestamp_format   = logging_sftp.value["timestamp_format"]
      user               = logging_sftp.value["user"]
    }
  }

  dynamic "papertrail" {
    for_each = var.papertrail
    content {
      address            = papertrail.value["address"]
      format             = papertrail.value["format"]
      name               = papertrail.value["name"]
      placement          = papertrail.value["placement"]
      port               = papertrail.value["port"]
      response_condition = papertrail.value["response_condition"]
    }
  }

  dynamic "request_setting" {
    for_each = var.request_setting
    content {
      action            = request_setting.value["action"]
      bypass_busy_wait  = request_setting.value["bypass_busy_wait"]
      default_host      = request_setting.value["default_host"]
      force_miss        = request_setting.value["force_miss"]
      force_ssl         = request_setting.value["force_ssl"]
      geo_headers       = request_setting.value["geo_headers"]
      hash_keys         = request_setting.value["hash_keys"]
      max_stale_age     = request_setting.value["max_stale_age"]
      name              = request_setting.value["name"]
      request_condition = request_setting.value["request_condition"]
      timer_support     = request_setting.value["timer_support"]
      xff               = request_setting.value["xff"]
    }
  }

  dynamic "response_object" {
    for_each = var.response_object
    content {
      cache_condition   = response_object.value["cache_condition"]
      content           = response_object.value["content"]
      content_type      = response_object.value["content_type"]
      name              = response_object.value["name"]
      request_condition = response_object.value["request_condition"]
      response          = response_object.value["response"]
      status            = response_object.value["status"]
    }
  }

  dynamic "s3logging" {
    for_each = var.s3logging
    content {
      bucket_name                       = s3logging.value["bucket_name"]
      domain                            = s3logging.value["domain"]
      format                            = s3logging.value["format"]
      format_version                    = s3logging.value["format_version"]
      gzip_level                        = s3logging.value["gzip_level"]
      message_type                      = s3logging.value["message_type"]
      name                              = s3logging.value["name"]
      path                              = s3logging.value["path"]
      period                            = s3logging.value["period"]
      placement                         = s3logging.value["placement"]
      public_key                        = s3logging.value["public_key"]
      redundancy                        = s3logging.value["redundancy"]
      response_condition                = s3logging.value["response_condition"]
      s3_access_key                     = s3logging.value["s3_access_key"]
      s3_secret_key                     = s3logging.value["s3_secret_key"]
      server_side_encryption            = s3logging.value["server_side_encryption"]
      server_side_encryption_kms_key_id = s3logging.value["server_side_encryption_kms_key_id"]
      timestamp_format                  = s3logging.value["timestamp_format"]
    }
  }

  dynamic "snippet" {
    for_each = var.snippet
    content {
      content  = snippet.value["content"]
      name     = snippet.value["name"]
      priority = snippet.value["priority"]
      type     = snippet.value["type"]
    }
  }

  dynamic "splunk" {
    for_each = var.splunk
    content {
      format             = splunk.value["format"]
      format_version     = splunk.value["format_version"]
      name               = splunk.value["name"]
      placement          = splunk.value["placement"]
      response_condition = splunk.value["response_condition"]
      tls_ca_cert        = splunk.value["tls_ca_cert"]
      tls_hostname       = splunk.value["tls_hostname"]
      token              = splunk.value["token"]
      url                = splunk.value["url"]
    }
  }

  dynamic "sumologic" {
    for_each = var.sumologic
    content {
      format             = sumologic.value["format"]
      format_version     = sumologic.value["format_version"]
      message_type       = sumologic.value["message_type"]
      name               = sumologic.value["name"]
      placement          = sumologic.value["placement"]
      response_condition = sumologic.value["response_condition"]
      url                = sumologic.value["url"]
    }
  }

  dynamic "syslog" {
    for_each = var.syslog
    content {
      address            = syslog.value["address"]
      format             = syslog.value["format"]
      format_version     = syslog.value["format_version"]
      message_type       = syslog.value["message_type"]
      name               = syslog.value["name"]
      placement          = syslog.value["placement"]
      port               = syslog.value["port"]
      response_condition = syslog.value["response_condition"]
      tls_ca_cert        = syslog.value["tls_ca_cert"]
      tls_client_cert    = syslog.value["tls_client_cert"]
      tls_client_key     = syslog.value["tls_client_key"]
      tls_hostname       = syslog.value["tls_hostname"]
      token              = syslog.value["token"]
      use_tls            = syslog.value["use_tls"]
    }
  }

  dynamic "vcl" {
    for_each = var.vcl
    content {
      content = vcl.value["content"]
      main    = vcl.value["main"]
      name    = vcl.value["name"]
    }
  }

}

