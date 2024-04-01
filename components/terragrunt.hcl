locals {
  aws_profile        = get_env("AWS_PROFILE")
  aws_region         = "eu-west-2"
  environment        = get_env("TG_ENVIRONMENT", "")
  environments       = get_env("TG_ENVIRONMENTS", "{}")
  terraform_version  = file("../.terraform-version")
  terragrunt_version = file("../.terragrunt-version")
  tfstate_bucket     = "bezero-infrastructure-tfstate-${get_aws_account_id()}"
  tfstate_key        = "${path_relative_to_include()}/terraform.tfstate"

  tags = {
    environment = local.environment
  }
}

inputs = {
  tags = local.tags
}

remote_state {
  backend = "s3"
  config = {
    bucket                 = local.tfstate_bucket
    dynamodb_table         = "terraform_state_locks"
    dynamodb_table_tags    = local.tags
    encrypt                = true
    key                    = local.tfstate_key
    profile                = local.aws_profile
    region                 = local.aws_region
    s3_bucket_tags         = local.tags
    skip_bucket_versioning = true
  }
  generate = {
    if_exists = "overwrite"
    path      = "remote_state.tf"
  }
}

generate provider {
  contents  = templatefile("../.providers.tftpl", { aws_profile = local.aws_profile, aws_region = local.aws_region })
  if_exists = "overwrite"
  path      = "temp_providers.tf"
}
