terraform {
  source = "../../../modules//organization"
}

include {
  path = find_in_parent_folders()
}

locals {
  global_vars = read_terragrunt_config(find_in_parent_folders("terragrunt.hcl"))
  root_vars   = read_terragrunt_config(find_in_parent_folders("root.hcl"))

  tags = merge(
    local.global_vars.inputs.tags,
    local.root_vars.inputs.tags,
    {
      component = "root/organization"
    }
  )
}

inputs = {
  tags = local.tags
}
