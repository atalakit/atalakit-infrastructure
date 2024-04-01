locals {
  tags = {
    component-root = "root"
    allow-delete   = false
  }
}

inputs = {
  tags = local.tags
}
