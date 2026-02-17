variable "region" {
  description = "AWS region for resources"
  type        = string
  default     = "ap-southeast-2"
}

variable "cluster_name" {
  type    = string
  default = "eks-1"
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
  description = "ACM certificate ARN for Argo CD ingress HTTPS. Leave empty to skip creating ingress with TLS."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "cognito_user_username" {
  description = "Username for the Cognito user. If not provided, will be auto-generated as {cluster_name}-user"
  type        = string
  default     = null
}
