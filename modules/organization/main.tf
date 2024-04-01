resource "aws_organizations_organization" "org" {
  aws_service_access_principals = [
    "account.amazonaws.com",
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "sso.amazonaws.com",
  ]

  feature_set = "ALL"
}

import {
  to = aws_organizations_organization.org
  id = "o-vjgtipv7lk"
}
