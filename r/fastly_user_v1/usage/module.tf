module "fastly_user_v1" {
  source = "./modules/fastly/r/fastly_user_v1"

  # login - (required) is a type of string
  login = null
  # name - (required) is a type of string
  name = null
  # role - (optional) is a type of string
  role = null
}
