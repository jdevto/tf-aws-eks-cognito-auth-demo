# Construct platform domain (e.g., platform.example.com)
locals {
  platform_domain = "${var.platform_subdomain}.${var.domain_name}"
}

# Cognito User Pool
resource "aws_cognito_user_pool" "this" {
  name = var.user_pool_name != null ? var.user_pool_name : "${var.cluster_name}-user-pool"

  # Enable OIDC
  schema {
    name                = "email"
    attribute_data_type = "String"
    required            = true
    mutable             = true
  }

  # Auto-verify email
  auto_verified_attributes = ["email"]

  # Email configuration - use Cognito default email service
  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }

  # Password policy
  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  tags = var.tags
}

# Cognito User Pool Client
resource "aws_cognito_user_pool_client" "this" {
  name         = "${var.cluster_name}-client"
  user_pool_id = aws_cognito_user_pool.this.id

  # OAuth configuration
  # For browser-based OIDC flows (like ArgoCD), use public client (no secret)
  # PKCE is automatically used by modern OAuth clients
  generate_secret = false

  allowed_oauth_flows = [
    "code" # Authorization code flow only (implicit is deprecated)
  ]

  allowed_oauth_scopes = [
    "openid",
    "email",
    "profile"
  ]

  # Enable groups in token (requires explicit configuration)
  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  allowed_oauth_flows_user_pool_client = true

  # Explicit auth flows required for public clients and hosted UI
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH"
  ]

  # Supported identity providers - must include COGNITO for hosted UI
  supported_identity_providers = ["COGNITO"]

  # Callback URLs for ALB OAuth and ArgoCD OIDC
  callback_urls = [
    "https://${local.platform_domain}/oauth2/idpresponse",                    # ALB OAuth callback
    "https://${local.platform_domain}${var.argocd_path_prefix}/auth/callback" # ArgoCD OIDC callback
  ]

  # Logout URLs
  logout_urls = [
    "https://${local.platform_domain}/",
    "https://${local.platform_domain}${var.argocd_path_prefix}" # ArgoCD logout
  ]

  # Token validity (values are in the units specified by token_validity_units)
  # Since token_validity_units specifies "hours" for access_token and id_token,
  # these values are in hours. 1 = 1 hour, 60 = 60 hours (max 24h)
  access_token_validity  = 1  # 1 hour
  id_token_validity      = 1  # 1 hour
  refresh_token_validity = 30 # 30 days

  # Prevent user existence errors
  prevent_user_existence_errors = "ENABLED"

  # Read attributes
  # Note: Groups are automatically included in ID token when users are assigned to groups
  read_attributes = [
    "email"
  ]

  # Write attributes
  write_attributes = [
    "email"
  ]
}

# Cognito User Pool Domain
# Use random suffix if domain_prefix not provided to avoid conflicts
resource "random_string" "domain_suffix" {
  count   = var.domain_prefix == null ? 1 : 0
  length  = 6
  special = false
  upper   = false
}

resource "aws_cognito_user_pool_domain" "this" {
  domain       = var.domain_prefix != null ? var.domain_prefix : "${var.cluster_name}-auth-${random_string.domain_suffix[0].result}"
  user_pool_id = aws_cognito_user_pool.this.id
}

# Cognito User Groups
resource "aws_cognito_user_group" "argocd_admin" {
  name         = "argocd-admin"
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "ArgoCD administrators with full access"
}

resource "aws_cognito_user_group" "argocd_platform" {
  name         = "argocd-platform"
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "ArgoCD platform team - manage clusters, repos, projects"
}

resource "aws_cognito_user_group" "argocd_devops" {
  name         = "argocd-devops"
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "ArgoCD DevOps team - manage applications in specific projects"
}

resource "aws_cognito_user_group" "argocd_auditor" {
  name         = "argocd-auditor"
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "ArgoCD auditors with read-only access"
}
