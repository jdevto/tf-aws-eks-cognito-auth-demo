variable "namespace" {
  type        = string
  default     = "default"
  description = "Kubernetes namespace for the landing page"
}

variable "subnet_ids" {
  type        = list(string)
  description = "List of subnet IDs for ALB (should be public subnets for internet-facing ALB)"
}

variable "shared_alb_ingress_group_name" {
  type        = string
  description = "Name of the ingress group for shared ALB"
}

variable "enable_https" {
  type        = bool
  default     = false
  description = "Enable HTTPS for landing page ingress using ACM certificate"
}

variable "certificate_arn" {
  type        = string
  default     = ""
  description = "ACM certificate ARN for HTTPS. Required when enable_https is true."
}

variable "ssl_redirect" {
  type        = bool
  default     = true
  description = "Redirect HTTP to HTTPS when enable_https is true"
}

variable "shared_alb_security_group_id" {
  type        = string
  default     = ""
  description = "Security group ID for shared ALB with IP restrictions. If provided, will be attached to the ALB."
}

variable "argocd_path_prefix" {
  type        = string
  default     = "/argocd"
  description = "Path prefix for ArgoCD links in the landing page"
}

variable "favicon_path" {
  type        = string
  default     = null
  description = "Path to favicon.svg file. If null, a default favicon will be used. Path should be relative to the module directory."
}
