module "fastly_service_v1" {
  source = "./modules/fastly/r/fastly_service_v1"

  # activate - (optional) is a type of bool
  activate = null
  # comment - (optional) is a type of string
  comment = null
  # default_host - (optional) is a type of string
  default_host = null
  # default_ttl - (optional) is a type of number
  default_ttl = null
  # force_destroy - (optional) is a type of bool
  force_destroy = null
  # name - (required) is a type of string
  name = null
  # version_comment - (optional) is a type of string
  version_comment = null

  acl = [{
    acl_id = null
    name   = null
  }]

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
    request_condition     = null
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
    dataset            = null
    email              = null
    format             = null
    name               = null
    placement          = null
    project_id         = null
    response_condition = null
    secret_key         = null
    table              = null
    template           = null
  }]

  blobstoragelogging = [{
    account_name       = null
    container          = null
    format             = null
    format_version     = null
    gzip_level         = null
    message_type       = null
    name               = null
    path               = null
    period             = null
    placement          = null
    public_key         = null
    response_condition = null
    sas_token          = null
    timestamp_format   = null
  }]

  cache_setting = [{
    action          = null
    cache_condition = null
    name            = null
    stale_ttl       = null
    ttl             = null
  }]

  condition = [{
    name      = null
    priority  = null
    statement = null
    type      = null
  }]

  dictionary = [{
    dictionary_id = null
    name          = null
    write_only    = null
  }]

  director = [{
    backends = []
    capacity = null
    comment  = null
    name     = null
    quorum   = null
    retries  = null
    shield   = null
    type     = null
  }]

  domain = [{
    comment = null
    name    = null
  }]

  dynamicsnippet = [{
    name       = null
    priority   = null
    snippet_id = null
    type       = null
  }]

  gcslogging = [{
    bucket_name        = null
    email              = null
    format             = null
    gzip_level         = null
    message_type       = null
    name               = null
    path               = null
    period             = null
    placement          = null
    response_condition = null
    secret_key         = null
    timestamp_format   = null
  }]

  gzip = [{
    cache_condition = null
    content_types   = []
    extensions      = []
    name            = null
  }]

  header = [{
    action             = null
    cache_condition    = null
    destination        = null
    ignore_if_set      = null
    name               = null
    priority           = null
    regex              = null
    request_condition  = null
    response_condition = null
    source             = null
    substitution       = null
    type               = null
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
    format              = null
    format_version      = null
    header_name         = null
    header_value        = null
    json_format         = null
    message_type        = null
    method              = null
    name                = null
    placement           = null
    request_max_bytes   = null
    request_max_entries = null
    response_condition  = null
    tls_ca_cert         = null
    tls_client_cert     = null
    tls_client_key      = null
    tls_hostname        = null
    url                 = null
  }]

  logentries = [{
    format             = null
    format_version     = null
    name               = null
    placement          = null
    port               = null
    response_condition = null
    token              = null
    use_tls            = null
  }]

  logging_cloudfiles = [{
    access_key         = null
    bucket_name        = null
    format             = null
    format_version     = null
    gzip_level         = null
    message_type       = null
    name               = null
    path               = null
    period             = null
    placement          = null
    public_key         = null
    region             = null
    response_condition = null
    timestamp_format   = null
    user               = null
  }]

  logging_datadog = [{
    format             = null
    format_version     = null
    name               = null
    placement          = null
    region             = null
    response_condition = null
    token              = null
  }]

  logging_digitalocean = [{
    access_key         = null
    bucket_name        = null
    domain             = null
    format             = null
    format_version     = null
    gzip_level         = null
    message_type       = null
    name               = null
    path               = null
    period             = null
    placement          = null
    public_key         = null
    response_condition = null
    secret_key         = null
    timestamp_format   = null
  }]

  logging_elasticsearch = [{
    format              = null
    format_version      = null
    index               = null
    name                = null
    password            = null
    pipeline            = null
    placement           = null
    request_max_bytes   = null
    request_max_entries = null
    response_condition  = null
    tls_ca_cert         = null
    tls_client_cert     = null
    tls_client_key      = null
    tls_hostname        = null
    url                 = null
    user                = null
  }]

  logging_ftp = [{
    address            = null
    format             = null
    format_version     = null
    gzip_level         = null
    message_type       = null
    name               = null
    password           = null
    path               = null
    period             = null
    placement          = null
    port               = null
    public_key         = null
    response_condition = null
    timestamp_format   = null
    user               = null
  }]

  logging_googlepubsub = [{
    format             = null
    format_version     = null
    name               = null
    placement          = null
    project_id         = null
    response_condition = null
    secret_key         = null
    topic              = null
    user               = null
  }]

  logging_heroku = [{
    format             = null
    format_version     = null
    name               = null
    placement          = null
    response_condition = null
    token              = null
    url                = null
  }]

  logging_honeycomb = [{
    dataset            = null
    format             = null
    format_version     = null
    name               = null
    placement          = null
    response_condition = null
    token              = null
  }]

  logging_kafka = [{
    brokers            = null
    compression_codec  = null
    format             = null
    format_version     = null
    name               = null
    placement          = null
    required_acks      = null
    response_condition = null
    tls_ca_cert        = null
    tls_client_cert    = null
    tls_client_key     = null
    tls_hostname       = null
    topic              = null
    use_tls            = null
  }]

  logging_loggly = [{
    format             = null
    format_version     = null
    name               = null
    placement          = null
    response_condition = null
    token              = null
  }]

  logging_logshuttle = [{
    format             = null
    format_version     = null
    name               = null
    placement          = null
    response_condition = null
    token              = null
    url                = null
  }]

  logging_newrelic = [{
    format             = null
    format_version     = null
    name               = null
    placement          = null
    response_condition = null
    token              = null
  }]

  logging_openstack = [{
    access_key         = null
    bucket_name        = null
    format             = null
    format_version     = null
    gzip_level         = null
    message_type       = null
    name               = null
    path               = null
    period             = null
    placement          = null
    public_key         = null
    response_condition = null
    timestamp_format   = null
    url                = null
    user               = null
  }]

  logging_scalyr = [{
    format             = null
    format_version     = null
    name               = null
    placement          = null
    region             = null
    response_condition = null
    token              = null
  }]

  logging_sftp = [{
    address            = null
    format             = null
    format_version     = null
    gzip_level         = null
    message_type       = null
    name               = null
    password           = null
    path               = null
    period             = null
    placement          = null
    port               = null
    public_key         = null
    response_condition = null
    secret_key         = null
    ssh_known_hosts    = null
    timestamp_format   = null
    user               = null
  }]

  papertrail = [{
    address            = null
    format             = null
    name               = null
    placement          = null
    port               = null
    response_condition = null
  }]

  request_setting = [{
    action            = null
    bypass_busy_wait  = null
    default_host      = null
    force_miss        = null
    force_ssl         = null
    geo_headers       = null
    hash_keys         = null
    max_stale_age     = null
    name              = null
    request_condition = null
    timer_support     = null
    xff               = null
  }]

  response_object = [{
    cache_condition   = null
    content           = null
    content_type      = null
    name              = null
    request_condition = null
    response          = null
    status            = null
  }]

  s3logging = [{
    bucket_name                       = null
    domain                            = null
    format                            = null
    format_version                    = null
    gzip_level                        = null
    message_type                      = null
    name                              = null
    path                              = null
    period                            = null
    placement                         = null
    public_key                        = null
    redundancy                        = null
    response_condition                = null
    s3_access_key                     = null
    s3_secret_key                     = null
    server_side_encryption            = null
    server_side_encryption_kms_key_id = null
    timestamp_format                  = null
  }]

  snippet = [{
    content  = null
    name     = null
    priority = null
    type     = null
  }]

  splunk = [{
    format             = null
    format_version     = null
    name               = null
    placement          = null
    response_condition = null
    tls_ca_cert        = null
    tls_hostname       = null
    token              = null
    url                = null
  }]

  sumologic = [{
    format             = null
    format_version     = null
    message_type       = null
    name               = null
    placement          = null
    response_condition = null
    url                = null
  }]

  syslog = [{
    address            = null
    format             = null
    format_version     = null
    message_type       = null
    name               = null
    placement          = null
    port               = null
    response_condition = null
    tls_ca_cert        = null
    tls_client_cert    = null
    tls_client_key     = null
    tls_hostname       = null
    token              = null
    use_tls            = null
  }]

  vcl = [{
    content = null
    main    = null
    name    = null
  }]
}
