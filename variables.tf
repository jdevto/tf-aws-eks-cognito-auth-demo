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
  default = "1.34"
}

variable "enable_ebs_csi_driver" {
  description = "Whether to install AWS EBS CSI Driver"
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

variable "enable_shared_alb" {
  description = "Enable shared ALB functionality. When true, sets up shared ALB for multiple services to use."
  type        = bool
  default     = false
}

variable "aws_auth_map_users" {
  type = list(object({
    userarn  = string
    username = string
    groups   = list(string)
  }))
  default     = []
  description = "List of IAM users to add to aws-auth ConfigMap for Kubernetes access"
}

variable "aws_auth_map_roles" {
  type = list(object({
    rolearn  = string
    username = string
    groups   = list(string)
  }))
  default     = []
  description = "List of IAM roles to add to aws-auth ConfigMap for Kubernetes access"
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
