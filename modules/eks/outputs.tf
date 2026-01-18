output "cluster_name" {
  value = aws_eks_cluster.this.name
}

output "cluster_endpoint" {
  value = aws_eks_cluster.this.endpoint
}

output "cluster_ca_data" {
  value = aws_eks_cluster.this.certificate_authority[0].data
}

output "cluster_ip_family" {
  description = "The IP family used by the cluster (e.g. ipv4 or ipv6)"
  value       = try(aws_eks_cluster.this.kubernetes_network_config[0].ip_family, null)
}

output "cluster_service_cidr" {
  description = "The IPv4 CIDR block where Kubernetes pod and service IP addresses are assigned from"
  value       = try(aws_eks_cluster.this.kubernetes_network_config[0].service_ipv4_cidr, null)
}

output "cluster_service_ipv6_cidr" {
  description = "The IPv6 CIDR block where Kubernetes pod and service IP addresses are assigned from (when ip_family is ipv6)"
  value       = try(aws_eks_cluster.this.kubernetes_network_config[0].service_ipv6_cidr, null)
}

output "aws_lb_controller_role_arn" {
  value       = aws_iam_role.aws_lb_controller.arn
  description = "IAM role ARN for AWS Load Balancer Controller"
}

output "oidc_provider_arn" {
  value       = aws_iam_openid_connect_provider.eks.arn
  description = "ARN of the EKS OIDC provider"
}

output "ebs_csi_driver_role_arn" {
  value       = var.enable_ebs_csi_driver ? aws_iam_role.ebs_csi_driver[0].arn : null
  description = "IAM role ARN for EBS CSI Driver"
}
