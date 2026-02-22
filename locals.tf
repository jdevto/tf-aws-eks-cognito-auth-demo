locals {
  name = "${var.cluster_name}-${random_id.suffix.hex}"

  cognito_domain_prefix = "argocd-test"
  argocd_host           = "${local.cognito_domain_prefix}.${var.domain_name}"
  argocd_base_url       = "https://${local.argocd_host}"

  common_tags = merge(
    var.tags,
    {
      Name        = var.cluster_name
      Environment = "dev"
      Project     = "test"
    }
  )
}
