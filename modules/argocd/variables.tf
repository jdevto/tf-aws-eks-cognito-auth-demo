variable "namespace" {
  type    = string
  default = "argocd"
}

variable "chart_version" {
  type        = string
  default     = "0.1.4"
  description = "Version of the k8sforge/argocd-chart Helm chart"
}

variable "aws_region" {
  type = string
}

variable "cluster_name" {
  type = string
}

variable "subnet_ids" {
  type        = list(string)
  description = "List of subnet IDs for ALB (should be public subnets for internet-facing ALB)"
}

variable "enable_https" {
  type        = bool
  default     = false
  description = "Enable HTTPS for ArgoCD ingress using ACM certificate. If true, requires certificate_arn."
}

variable "ssl_redirect" {
  type        = bool
  default     = true
  description = "Redirect HTTP to HTTPS when enable_https is true. If false, both HTTP and HTTPS are accessible."
}

variable "certificate_arn" {
  type        = string
  default     = ""
  description = "ACM certificate ARN for HTTPS. Required when enable_https is true."
}

variable "shared_alb_ingress_group_name" {
  type        = string
  default     = "shared-alb"
  description = "Name of the ingress group for shared ALB. All ingresses with this group name will share the same ALB."
}

variable "platform_domain" {
  type        = string
  description = "Full platform domain name (e.g., platform.example.com). This is the complete domain where ArgoCD will be accessible."
}

variable "shared_alb_security_group_id" {
  type        = string
  default     = ""
  description = "Security group ID for shared ALB with IP restrictions. Empty if IP restrictions are not configured."
}

variable "argocd_path_prefix" {
  type        = string
  default     = "/argocd"
  description = "Path prefix for ArgoCD (e.g., /argocd). Used for ingress paths and health checks."
}

variable "enable_cognito_oidc" {
  type        = bool
  default     = false
  description = "Enable Cognito OIDC authentication for ArgoCD"
}

variable "cognito_user_pool_id" {
  type        = string
  default     = ""
  description = "Cognito User Pool ID for OIDC configuration"
}

variable "cognito_user_pool_client_id" {
  type        = string
  default     = ""
  description = "Cognito User Pool Client ID for OIDC configuration"
}

variable "cognito_user_pool_client_secret" {
  type        = string
  default     = ""
  sensitive   = true
  description = "Cognito User Pool Client Secret for OIDC configuration"
}

variable "cognito_oidc_issuer_url" {
  type        = string
  default     = ""
  description = "Cognito OIDC Issuer URL for ArgoCD OIDC configuration"
}

variable "cognito_user_pool_arn" {
  type        = string
  default     = ""
  description = "ARN of the Cognito User Pool for ALB authentication"
}

variable "cognito_user_pool_domain" {
  type        = string
  default     = ""
  description = "Domain of the Cognito User Pool for ALB authentication"
}

variable "cognito_user_pool_domain_url" {
  type        = string
  default     = ""
  description = "Full URL of the Cognito User Pool Domain (e.g., https://domain.auth.region.amazoncognito.com)"
}

variable "rbac_policy_file" {
  type        = string
  default     = ""
  description = "Path to custom RBAC policy CSV file. If empty, uses default rbac-policy.csv in module directory."
}
