output "platform_url" {
  description = <<-EOT
    Platform URL with protocol (http:// or https://).
    Notes:
    - Empty until a Kubernetes Ingress triggers ALB creation
    - Route53 record may require a second terraform apply
  EOT
  value = var.enable_shared_alb ? (
    var.enable_https ? "https://${module.route53_platform[0].custom_domain}" : "http://${module.route53_platform[0].custom_domain}"
  ) : ""
}

output "shared_alb_dns_name" {
  description = <<-EOT
    Shared ALB DNS name.
    Notes:
    - Empty until a Kubernetes Ingress triggers ALB creation
    - Route53 record depends on this, may require second apply
  EOT
  value       = module.eks.shared_alb_dns_name
}

output "argocd_username" {
  description = "ArgoCD username. Returns null if ArgoCD module is not enabled or not available."
  value       = try(module.argocd.argocd_username, null)
}

output "argocd_password" {
  description = "ArgoCD password. Returns null if ArgoCD module is not enabled or not available."
  value       = try(module.argocd.argocd_password, null)
  sensitive   = true
}

output "cognito_user_pool_id" {
  description = "Cognito User Pool ID. Returns null if Cognito authentication is not enabled."
  value       = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_id : null
}

output "cognito_user_pool_domain" {
  description = "Cognito User Pool Domain. Returns null if Cognito authentication is not enabled."
  value       = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_domain : null
}

output "cognito_hosted_ui_url" {
  description = "Cognito Hosted UI URL. Returns null if Cognito authentication is not enabled."
  value       = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_domain_url : null
}

output "cognito_oidc_issuer_url" {
  description = "Cognito OIDC Issuer URL for ArgoCD configuration. Returns null if Cognito authentication is not enabled."
  value       = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].oidc_issuer_url : null
}
