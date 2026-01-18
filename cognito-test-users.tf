# Cognito Test Users
# Manages test users for development/testing via Terraform.
# Configure users in terraform.tfvars: cognito_test_users
# Set enable_cognito_test_users = false to disable.

locals {
  test_users_by_email = var.enable_shared_alb && var.enable_cognito_auth && var.enable_cognito_test_users ? {
    for u in var.cognito_test_users : u.email => u
  } : {}
}

resource "random_password" "test_user_password" {
  for_each = local.test_users_by_email

  length           = 16
  special          = true
  upper            = true
  lower            = true
  numeric          = true
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_cognito_user" "test" {
  for_each = local.test_users_by_email

  user_pool_id = module.cognito[0].user_pool_id
  username     = each.value.username

  attributes = {
    email          = each.value.email
    email_verified = "true"
  }

  temporary_password = random_password.test_user_password[each.key].result

  lifecycle {
    ignore_changes = [temporary_password]
  }

  depends_on = [module.cognito]
}

resource "aws_cognito_user_in_group" "test" {
  for_each = aws_cognito_user.test

  user_pool_id = module.cognito[0].user_pool_id
  group_name   = local.test_users_by_email[each.key].group_name
  username     = each.value.username

  depends_on = [aws_cognito_user.test, module.cognito]
}
