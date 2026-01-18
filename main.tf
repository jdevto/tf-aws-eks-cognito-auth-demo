module "vpc" {
  source = "cloudbuildlab/vpc/aws"

  vpc_name           = local.name
  vpc_cidr           = "10.0.0.0/16"
  availability_zones = ["${var.region}a", "${var.region}b"]

  public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnet_cidrs = ["10.0.101.0/24", "10.0.102.0/24"]

  # Enable IPv6 support
  assign_generated_ipv6_cidr_block = true

  # Enable Internet Gateway & NAT Gateway
  create_igw       = true
  nat_gateway_type = "single"

  enable_eks_tags  = true
  eks_cluster_name = var.cluster_name

  tags = local.common_tags
}

module "eks" {
  source = "tfstack/eks-basic/aws"

  name               = var.cluster_name
  kubernetes_version = var.cluster_version
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = concat(module.vpc.public_subnet_ids, module.vpc.private_subnet_ids)

  endpoint_public_access = true

  access_entries                      = var.access_entries
  enable_aws_load_balancer_controller = var.enable_aws_load_balancer_controller

  addons = {
    coredns = {
      addon_version = "v1.13.2-eksbuild.1"
    }
    eks-pod-identity-agent = {
      before_compute = true
      addon_version  = "v1.3.10-eksbuild.2"
    }
    kube-proxy = {
      addon_version = "v1.35.0-eksbuild.2"
    }
    vpc-cni = {
      before_compute = true
      addon_version  = "v1.21.1-eksbuild.3"
      configuration_values = jsonencode({
        enableNetworkPolicy = "true"
        nodeAgent = {
          enablePolicyEventLogs = "true"
        }
      })
    }
  }

  eks_managed_node_groups = {
    one = {
      name           = "node-group-1"
      ami_type       = "AL2023_x86_64_STANDARD"
      instance_types = ["t3a.large"]

      min_size     = 3
      max_size     = 3
      desired_size = 3

      metadata_options = {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 1
      }
    }
  }

  depends_on = [module.vpc]
}

# module "shared_alb" {
#   source = "./modules/shared-alb"

#   count = var.enable_shared_alb ? 1 : 0

#   cluster_name                  = local.cluster_name
#   vpc_id                        = module.vpc.vpc_id
#   shared_alb_ingress_group_name = "platform"
#   shared_alb_allowed_ips        = var.shared_alb_allowed_ips

#   tags = local.common_tags

#   depends_on = [
#     module.eks,
#     module.vpc,
#     module.cognito
#   ]
# }

# module "route53_platform" {
#   source = "./modules/route53"

#   count = var.enable_shared_alb ? 1 : 0

#   name         = "platform"
#   domain_name  = var.domain_name
#   alb_dns_name = module.shared_alb[0].shared_alb_dns_name
#   alb_zone_id  = module.shared_alb[0].shared_alb_zone_id

#   depends_on = [module.shared_alb]
# }

# module "landing_page" {
#   source = "./modules/landing-page"

#   count = var.enable_shared_alb ? 1 : 0

#   subnet_ids                    = module.vpc.public_subnet_ids
#   shared_alb_ingress_group_name = module.shared_alb[0].shared_alb_ingress_group_name
#   shared_alb_security_group_id  = module.shared_alb[0].shared_alb_security_group_id
#   enable_https                  = var.enable_https
#   certificate_arn               = var.enable_https ? var.certificate_arn : ""
#   ssl_redirect                  = var.enable_https
#   argocd_path_prefix            = "/argocd"

#   depends_on = [
#     module.eks,
#     module.vpc,
#     module.shared_alb
#   ]
# }

# module "cognito" {
#   source = "./modules/cognito"

#   count = var.enable_shared_alb && var.enable_cognito_auth ? 1 : 0

#   cluster_name       = local.cluster_name
#   domain_name        = var.domain_name
#   platform_subdomain = "platform"
#   user_pool_name     = var.cognito_user_pool_name
#   domain_prefix      = var.cognito_domain_prefix
#   argocd_path_prefix = "/argocd"
#   tags               = local.common_tags

#   depends_on = [module.vpc]
# }

# # ArgoCD Module
# module "argocd" {
#   source = "./modules/argocd"

#   aws_region                    = var.region
#   cluster_name                  = module.eks.cluster_name
#   subnet_ids                    = module.vpc.public_subnet_ids
#   enable_https                  = var.enable_https
#   certificate_arn               = var.certificate_arn
#   ssl_redirect                  = var.enable_https
#   shared_alb_ingress_group_name = module.shared_alb[0].shared_alb_ingress_group_name
#   shared_alb_security_group_id  = module.shared_alb[0].shared_alb_security_group_id
#   platform_domain               = "platform.${var.domain_name}"

#   enable_cognito_oidc             = var.enable_shared_alb && var.enable_cognito_auth
#   cognito_user_pool_id            = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_id : ""
#   cognito_user_pool_client_id     = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_client_id : ""
#   cognito_user_pool_client_secret = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_client_secret : ""
#   cognito_oidc_issuer_url         = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].oidc_issuer_url : ""
#   cognito_user_pool_arn           = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_arn : ""
#   cognito_user_pool_domain        = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_domain : ""
#   cognito_user_pool_domain_url    = var.enable_shared_alb && var.enable_cognito_auth ? module.cognito[0].user_pool_domain_url : ""

#   depends_on = [
#     module.eks,
#     module.vpc,
#     module.shared_alb,
#     module.cognito
#   ]
# }
