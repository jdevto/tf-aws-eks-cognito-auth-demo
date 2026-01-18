variable "cluster_name" {
  type = string
}

variable "cluster_version" {
  type = string
}

variable "subnet_ids" {
  description = "Subnet IDs for EKS cluster control plane (should include both public and private)"
  type        = list(string)
}

variable "node_subnet_ids" {
  description = "Subnet IDs for EKS node groups (should be private subnets only for security)"
  type        = list(string)
  default     = null
}

variable "endpoint_public_access" {
  description = "Whether the Amazon EKS public API server endpoint is enabled"
  type        = bool
  default     = true
}

variable "public_access_cidrs" {
  description = "List of CIDR blocks that can access the Amazon EKS public API server endpoint"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "enabled_cluster_log_types" {
  description = "List of control plane logging types to enable"
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

variable "node_instance_types" {
  type    = list(string)
  default = ["t3.medium"]
}

variable "node_desired_size" {
  type    = number
  default = 2
}

variable "node_min_size" {
  type    = number
  default = 1
}

variable "node_max_size" {
  type    = number
  default = 3
}

variable "node_disk_size" {
  description = "Disk size in GiB for worker nodes"
  type        = number
  default     = 20
}

variable "node_update_max_unavailable" {
  description = "Maximum number of nodes unavailable during update"
  type        = number
  default     = 1
}

variable "node_remote_access_enabled" {
  description = "Whether to enable remote access to nodes"
  type        = bool
  default     = false
}

variable "node_remote_access_ssh_key" {
  description = "EC2 SSH key name for remote access"
  type        = string
  default     = null
}

variable "node_remote_access_security_groups" {
  description = "List of security group IDs for remote access"
  type        = list(string)
  default     = []
}

variable "node_labels" {
  description = "Key-value map of Kubernetes labels to apply to nodes"
  type        = map(string)
  default     = {}
}

variable "vpc_id" {
  description = "VPC ID where the cluster is deployed"
  type        = string
}

variable "enable_aws_lb_controller" {
  description = "Whether to install AWS Load Balancer Controller"
  type        = bool
  default     = true
}

variable "aws_lb_controller_helm_version" {
  description = "Version of the AWS Load Balancer Controller Helm chart"
  type        = string
  default     = "1.7.2"
}

variable "aws_lb_controller_helm_values" {
  description = "Additional Helm values for the AWS Load Balancer Controller"
  type        = map(string)
  default     = {}
}

variable "enable_ebs_csi_driver" {
  description = "Whether to install AWS EBS CSI Driver"
  type        = bool
  default     = false
}

variable "ebs_csi_driver_version" {
  description = "Version of the AWS EBS CSI Driver add-on"
  type        = string
  default     = null # Uses latest version
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "enable_shared_alb" {
  type        = bool
  default     = false
  description = "Enable shared ALB functionality. When true, sets up data sources and outputs for shared ALB discovery."
}

variable "shared_alb_ingress_group_name" {
  type        = string
  default     = "shared-alb"
  description = "Name of the ingress group for shared ALB. All ingresses with this group name will share the same ALB. Only used when enable_shared_alb is true."
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

# Cognito authentication variables (optional)
variable "enable_cognito_auth" {
  type        = bool
  default     = false
  description = "Enable Cognito authentication for ALB listener rules"
}

variable "cognito_user_pool_arn" {
  type        = string
  default     = ""
  description = "ARN of the Cognito User Pool for ALB authentication"
}

variable "cognito_user_pool_client_id" {
  type        = string
  default     = ""
  description = "ID of the Cognito User Pool Client for ALB authentication"
}

variable "cognito_user_pool_domain" {
  type        = string
  default     = ""
  description = "Domain of the Cognito User Pool for ALB authentication"
}

variable "enable_https" {
  type        = bool
  default     = false
  description = "Whether HTTPS is enabled (determines if HTTPS listener rules are created)"
}
