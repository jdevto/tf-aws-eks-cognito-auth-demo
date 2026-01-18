output "shared_alb_dns_name" {
  value = try(
    data.aws_lb.shared_alb_details[0].dns_name,
    ""
  )
  description = "Shared ALB DNS name (used by multiple services via ingress group name). Empty until ALB is created by AWS Load Balancer Controller."
}

output "shared_alb_zone_id" {
  value = try(
    data.aws_lb.shared_alb_details[0].zone_id,
    ""
  )
  description = "Shared ALB zone ID (used by multiple services via ingress group name). Empty until ALB is created by AWS Load Balancer Controller."
}

output "shared_alb_ingress_group_name" {
  value       = var.shared_alb_ingress_group_name
  description = "Name of the ingress group for shared ALB."
}

output "shared_alb_security_group_id" {
  value       = length(var.shared_alb_allowed_ips) > 0 ? aws_security_group.shared_alb[0].id : ""
  description = "Security group ID for shared ALB with IP restrictions. Empty if IP restrictions are not configured."
}
