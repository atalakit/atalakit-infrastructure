# Disable the terraform_required_providers rule as this is managed by Terragrunt
rule "terraform_required_providers" {
  enabled = false
}

rule "terraform_required_version" {
  enabled = false
}
