output "argocd_namespace" {
  value = var.namespace
}

output "argocd_server_service_name" {
  value = "argocd-server"
}

output "argocd_username" {
  value       = "admin"
  description = "ArgoCD admin username"
}

output "argocd_password" {
  value = try(
    base64decode(data.kubernetes_secret.argocd_admin.data["password"]),
    "Run: kubectl get secret -n argocd argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d"
  )
  sensitive   = false
  description = "ArgoCD admin password"
}

output "argocd_server_url" {
  value = coalesce(
    # Try to get from Ingress status first
    try(
      length(data.kubernetes_ingress_v1.argocd_server.status[0].load_balancer[0].ingress) > 0 ? (
        try(
          "http://${data.kubernetes_ingress_v1.argocd_server.status[0].load_balancer[0].ingress[0].hostname}/argocd",
          "http://${data.kubernetes_ingress_v1.argocd_server.status[0].load_balancer[0].ingress[0].ip}/argocd"
        )
      ) : null,
      null
    ),
    # Fallback message when Ingress status is not populated
    "Run: aws elbv2 describe-load-balancers --region ${var.aws_region} --query 'LoadBalancers[?contains(LoadBalancerName, `k8s-${var.shared_alb_ingress_group_name}`)].DNSName' --output text"
  )
  description = "ArgoCD server ALB URL (HTTP, insecure mode enabled, accessible at /argocd path). If showing a command, Ingress status is not populated yet."
}
