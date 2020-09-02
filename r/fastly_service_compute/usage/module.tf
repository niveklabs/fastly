module "fastly_service_compute" {
  source = "./modules/fastly/r/fastly_service_compute"

  # activate - (optional) is a type of bool
  activate = null
  # comment - (optional) is a type of string
  comment = null
  # force_destroy - (optional) is a type of bool
  force_destroy = null
  # name - (required) is a type of string
  name = null
  # version_comment - (optional) is a type of string
  version_comment = null

  backend = [{
    address               = null
    auto_loadbalance      = null
    between_bytes_timeout = null
    connect_timeout       = null
    error_threshold       = null
    first_byte_timeout    = null
    healthcheck           = null
    max_conn              = null
    max_tls_version       = null
    min_tls_version       = null
    name                  = null
    override_host         = null
    port                  = null
    shield                = null
    ssl_ca_cert           = null
    ssl_cert_hostname     = null
    ssl_check_cert        = null
    ssl_ciphers           = null
    ssl_client_cert       = null
    ssl_client_key        = null
    ssl_hostname          = null
    ssl_sni_hostname      = null
    use_ssl               = null
    weight                = null
  }]

  bigquerylogging = [{
    dataset    = null
    email      = null
    name       = null
    project_id = null
    secret_key = null
    table      = null
    template   = null
  }]

  blobstoragelogging = [{
    account_name     = null
    container        = null
    gzip_level       = null
    message_type     = null
    name             = null
    path             = null
    period           = null
    public_key       = null
    sas_token        = null
    timestamp_format = null
  }]

  domain = [{
    comment = null
    name    = null
  }]

  gcslogging = [{
    bucket_name      = null
    email            = null
    gzip_level       = null
    message_type     = null
    name             = null
    path             = null
    period           = null
    secret_key       = null
    timestamp_format = null
  }]

  healthcheck = [{
    check_interval    = null
    expected_response = null
    host              = null
    http_version      = null
    initial           = null
    method            = null
    name              = null
    path              = null
    threshold         = null
    timeout           = null
    window            = null
  }]

  httpslogging = [{
    content_type        = null
    header_name         = null
    header_value        = null
    json_format         = null
    message_type        = null
    method              = null
    name                = null
    request_max_bytes   = null
    request_max_entries = null
    tls_ca_cert         = null
    tls_client_cert     = null
    tls_client_key      = null
    tls_hostname        = null
    url                 = null
  }]

  logentries = [{
    name    = null
    port    = null
    token   = null
    use_tls = null
  }]

  logging_cloudfiles = [{
    access_key       = null
    bucket_name      = null
    gzip_level       = null
    message_type     = null
    name             = null
    path             = null
    period           = null
    public_key       = null
    region           = null
    timestamp_format = null
    user             = null
  }]

  logging_datadog = [{
    name   = null
    region = null
    token  = null
  }]

  logging_digitalocean = [{
    access_key       = null
    bucket_name      = null
    domain           = null
    gzip_level       = null
    message_type     = null
    name             = null
    path             = null
    period           = null
    public_key       = null
    secret_key       = null
    timestamp_format = null
  }]

  logging_elasticsearch = [{
    index               = null
    name                = null
    password            = null
    pipeline            = null
    request_max_bytes   = null
    request_max_entries = null
    tls_ca_cert         = null
    tls_client_cert     = null
    tls_client_key      = null
    tls_hostname        = null
    url                 = null
    user                = null
  }]

  logging_ftp = [{
    address          = null
    gzip_level       = null
    message_type     = null
    name             = null
    password         = null
    path             = null
    period           = null
    port             = null
    public_key       = null
    timestamp_format = null
    user             = null
  }]

  logging_googlepubsub = [{
    name       = null
    project_id = null
    secret_key = null
    topic      = null
    user       = null
  }]

  logging_heroku = [{
    name  = null
    token = null
    url   = null
  }]

  logging_honeycomb = [{
    dataset = null
    name    = null
    token   = null
  }]

  logging_kafka = [{
    brokers           = null
    compression_codec = null
    name              = null
    required_acks     = null
    tls_ca_cert       = null
    tls_client_cert   = null
    tls_client_key    = null
    tls_hostname      = null
    topic             = null
    use_tls           = null
  }]

  logging_loggly = [{
    name  = null
    token = null
  }]

  logging_logshuttle = [{
    name  = null
    token = null
    url   = null
  }]

  logging_newrelic = [{
    name  = null
    token = null
  }]

  logging_openstack = [{
    access_key       = null
    bucket_name      = null
    gzip_level       = null
    message_type     = null
    name             = null
    path             = null
    period           = null
    public_key       = null
    timestamp_format = null
    url              = null
    user             = null
  }]

  logging_scalyr = [{
    name   = null
    region = null
    token  = null
  }]

  logging_sftp = [{
    address          = null
    gzip_level       = null
    message_type     = null
    name             = null
    password         = null
    path             = null
    period           = null
    port             = null
    public_key       = null
    secret_key       = null
    ssh_known_hosts  = null
    timestamp_format = null
    user             = null
  }]

  package = [{
    filename         = null
    source_code_hash = null
  }]

  papertrail = [{
    address = null
    name    = null
    port    = null
  }]

  s3logging = [{
    bucket_name                       = null
    domain                            = null
    gzip_level                        = null
    message_type                      = null
    name                              = null
    path                              = null
    period                            = null
    public_key                        = null
    redundancy                        = null
    s3_access_key                     = null
    s3_secret_key                     = null
    server_side_encryption            = null
    server_side_encryption_kms_key_id = null
    timestamp_format                  = null
  }]

  splunk = [{
    name         = null
    tls_ca_cert  = null
    tls_hostname = null
    token        = null
    url          = null
  }]

  sumologic = [{
    message_type = null
    name         = null
    url          = null
  }]

  syslog = [{
    address         = null
    message_type    = null
    name            = null
    port            = null
    tls_ca_cert     = null
    tls_client_cert = null
    tls_client_key  = null
    tls_hostname    = null
    token           = null
    use_tls         = null
  }]
}
