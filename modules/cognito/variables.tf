variable "cluster_name" {
  description = "Cluster name for resource naming"
  type        = string
}

variable "domain_name" {
  description = "Base domain name (e.g., example.com). The platform subdomain will be constructed as platform.{domain_name}."
  type        = string
}

variable "platform_subdomain" {
  description = "Platform subdomain prefix (e.g., 'platform'). If not provided, defaults to 'platform'."
  type        = string
  default     = "platform"
}

variable "user_pool_name" {
  description = "Name for the Cognito User Pool"
  type        = string
  default     = null
}

variable "domain_prefix" {
  description = "Prefix for Cognito hosted UI domain. If not provided, will be auto-generated."
  type        = string
  default     = null
}

variable "argocd_path_prefix" {
  description = "Path prefix for ArgoCD (e.g., /argocd). Used to construct ArgoCD OIDC callback URL."
  type        = string
  default     = "/argocd"
}

variable "tags" {
  description = "Tags to apply to Cognito resources"
  type        = map(string)
  default     = {}
}
