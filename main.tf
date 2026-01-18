# VPC Module
module "vpc" {
  source = "./modules/vpc"

  name               = var.cluster_name
  cluster_name       = var.cluster_name
  availability_zones = ["${var.region}a", "${var.region}b"]

  tags = merge(local.common_tags, {
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
  })
}

# EKS Module
module "eks" {
  source = "./modules/eks"

  cluster_name                  = local.cluster_name
  cluster_version               = var.cluster_version
  enable_ebs_csi_driver         = var.enable_ebs_csi_driver
  enable_aws_lb_controller      = true # Enable AWS Load Balancer Controller for ALB support
  enable_shared_alb             = var.enable_shared_alb
  shared_alb_ingress_group_name = var.enable_shared_alb ? "platform" : ""
  # Cluster control plane can use both public and private subnets
  subnet_ids = concat(module.vpc.private_subnet_ids, module.vpc.public_subnet_ids)
  # Node groups should be in private subnets only for security
  node_subnet_ids = module.vpc.private_subnet_ids
  vpc_id          = module.vpc.vpc_id
  tags            = local.common_tags

  # AWS Auth ConfigMap - map IAM users and roles for Kubernetes access
  aws_auth_map_users = var.aws_auth_map_users
  aws_auth_map_roles = var.aws_auth_map_roles

  # Shared ALB IP restrictions
  shared_alb_allowed_ips = var.shared_alb_allowed_ips

  # Cognito authentication (optional)
  enable_cognito_auth         = var.enable_shared_alb && var.enable_cognito_auth
  cognito_user_pool_arn       = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_arn : ""
  cognito_user_pool_client_id = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_client_id : ""
  cognito_user_pool_domain    = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_domain : ""
  enable_https                = var.enable_https

  depends_on = [module.vpc]
}

module "route53_platform" {
  source = "./modules/route53"

  count = var.enable_shared_alb ? 1 : 0

  name         = "platform" # Creates: platform.example.com
  domain_name  = var.domain_name
  alb_dns_name = module.eks.shared_alb_dns_name
  alb_zone_id  = module.eks.shared_alb_zone_id
}

# Landing Page Module
module "landing_page" {
  source = "./modules/landing-page"

  count = var.enable_shared_alb ? 1 : 0

  subnet_ids                    = module.vpc.public_subnet_ids
  shared_alb_ingress_group_name = module.eks.shared_alb_ingress_group_name
  shared_alb_security_group_id  = module.eks.shared_alb_security_group_id
  enable_https                  = var.enable_https
  certificate_arn               = var.enable_https ? var.certificate_arn : ""
  ssl_redirect                  = var.enable_https

  # Path prefixes for service links
  argocd_path_prefix = "/argocd"

  depends_on = [
    module.eks,
    module.vpc
  ]
}

# Cognito Module
module "cognito" {
  source = "./modules/cognito"

  count = var.enable_shared_alb && var.enable_cognito_auth ? 1 : 0

  cluster_name       = local.cluster_name
  domain_name        = var.domain_name
  platform_subdomain = "platform" # Must match route53_platform module's name
  user_pool_name     = var.cognito_user_pool_name
  domain_prefix      = var.cognito_domain_prefix
  argocd_path_prefix = "/argocd" # Must match argocd module's argocd_path_prefix
  tags               = local.common_tags
}

# ALB Cognito Authentication is now handled in the EKS module
# (Listener rules are created directly in modules/eks/main.tf)

# ArgoCD Module
module "argocd" {
  source = "./modules/argocd"

  aws_region                    = var.region
  cluster_name                  = module.eks.cluster_name
  subnet_ids                    = module.vpc.public_subnet_ids
  enable_https                  = var.enable_https
  certificate_arn               = var.certificate_arn
  ssl_redirect                  = var.enable_https
  shared_alb_ingress_group_name = module.eks.shared_alb_ingress_group_name
  shared_alb_security_group_id  = module.eks.shared_alb_security_group_id
  platform_domain               = "platform.${var.domain_name}"

  # Cognito OIDC configuration (if enabled)
  enable_cognito_oidc             = var.enable_shared_alb && var.enable_cognito_auth
  cognito_user_pool_id            = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_id : ""
  cognito_user_pool_client_id     = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_client_id : ""
  cognito_user_pool_client_secret = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_client_secret : ""
  cognito_oidc_issuer_url         = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].oidc_issuer_url : ""

  depends_on = [
    module.eks,
    module.vpc
  ]
}
