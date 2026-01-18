variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where the cluster is deployed"
  type        = string
}

variable "shared_alb_ingress_group_name" {
  type        = string
  default     = "shared-alb"
  description = "Name of the ingress group for shared ALB. All ingresses with this group name will share the same ALB."
}

variable "shared_alb_allowed_ips" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "List of CIDR blocks allowed to access the shared ALB. If empty, all IPs are allowed. Example: [\"1.2.3.4/32\", \"10.0.0.0/8\"]"
}


variable "tags" {
  type    = map(string)
  default = {}
}
