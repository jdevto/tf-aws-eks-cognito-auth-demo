output "argocd_port_forward_command" {
  description = "Command to port forward to ArgoCD server"
  value       = <<-EOT
  aws eks update-kubeconfig --name ${var.cluster_name} --region ${var.region}
  kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d && echo
  kubectl port-forward svc/argo-cd-argocd-server -n argocd 8080:80
  EOT
}
