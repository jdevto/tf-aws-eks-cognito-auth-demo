variable "region" {
  description = "AWS region for resources"
  type        = string
  default     = "ap-southeast-2"
}

variable "cluster_name" {
  type    = string
  default = "test"
}

variable "cluster_version" {
  type    = string
  default = "1.35"
}

variable "access_entries" {
  description = "Map of access entries to add to the cluster"
  type = map(object({
    kubernetes_groups = optional(list(string))
    principal_arn     = string
    type              = optional(string, "STANDARD")
    user_name         = optional(string)
    tags              = optional(map(string), {})
    policy_associations = optional(map(object({
      policy_arn = string
      access_scope = object({
        namespaces = optional(list(string))
        type       = string
      })
    })), {})
  }))
  default = {}
}

variable "enable_aws_load_balancer_controller" {
  description = "Whether to create IAM role for AWS Load Balancer Controller (IRSA)"
  type        = bool
  default     = true
}

variable "domain_name" {
  description = "Domain name"
  type        = string
}

variable "enable_https" {
  description = "Enable HTTPS for ArgoCD and Atlantis ingress using ACM certificate"
  type        = bool
  default     = false
}

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS. Required when enable_https is true."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "shared_alb_allowed_ips" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "List of CIDR blocks allowed to access the shared ALB. If empty, all IPs are allowed. Example: [\"1.2.3.4/32\", \"10.0.0.0/8\"]"
}

variable "enable_cognito_auth" {
  description = "Enable AWS Cognito authentication for the shared ALB. Requires enable_shared_alb to be true."
  type        = bool
  default     = false
}

variable "cognito_user_pool_name" {
  description = "Name for the Cognito User Pool. If not provided, will be auto-generated as {cluster_name}-user-pool"
  type        = string
  default     = null
}

variable "cognito_domain_prefix" {
  description = "Prefix for Cognito hosted UI domain. If not provided, will be auto-generated as {cluster_name}-auth"
  type        = string
  default     = null
}

variable "enable_cognito_test_users" {
  description = "Enable creation of test users for development/testing. Set to false in production."
  type        = bool
  default     = false
}

variable "cognito_test_users" {
  description = "List of test users to create in Cognito. Each user must have email, username, and group_name."
  type = list(object({
    email      = string
    username   = string
    group_name = string
  }))
  default = []
}
