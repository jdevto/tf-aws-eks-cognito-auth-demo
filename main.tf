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

  enable_cluster_creator_admin_permissions = true
  access_entries                           = var.access_entries

  cloudwatch_log_group_force_destroy = true

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

  # Pod Identity for AWS Load Balancer Controller
  aws_load_balancer_controller_identity_type = "pod_identity"
  enable_aws_load_balancer_controller        = true
  aws_lb_controller_namespace                = "aws-load-balancer-controller"
  aws_lb_controller_service_account          = "aws-load-balancer-controller"

  # Pod Identity for External DNS
  external_dns_identity_type   = "pod_identity"
  enable_external_dns          = true
  external_dns_namespace       = "external-dns"
  external_dns_service_account = "external-dns"

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

module "cognito_user_pool" {
  source = "tfstack/cognito/aws//modules/user-pool"

  name          = "${var.cluster_name}-userpool"
  domain_prefix = local.cognito_domain_prefix
  app_clients   = { "${local.cognito_domain_prefix}" = {} } # optional: empty map = no clients

  user_pool_groups = { # optional: groups (cognito:groups in ID token)
    "admin"    = { description = "Admins", precedence = 1 }
    "readonly" = { description = "Read-only", precedence = 2 }
  }

  # Argo CD OIDC: callback must be <argocd-base>/auth/callback; logout = base URL
  callback_urls       = ["${local.argocd_base_url}/auth/callback"]
  logout_urls         = [local.argocd_base_url]
  allowed_oauth_flows = ["code"]

  tags = local.common_tags
}

resource "random_password" "demo_user" {
  count   = var.cognito_user_username != null ? 1 : 0
  length  = 16
  special = true
}

resource "aws_cognito_user" "demo" {
  count        = var.cognito_user_username != null ? 1 : 0
  user_pool_id = module.cognito_user_pool.user_pool_id
  username     = var.cognito_user_username

  attributes = {
    email          = var.cognito_user_username
    email_verified = "true"
  }

  temporary_password = random_password.demo_user[0].result
  message_action     = "SUPPRESS"
}

resource "aws_cognito_user_in_group" "demo" {
  count        = var.cognito_user_username != null ? 1 : 0
  user_pool_id = module.cognito_user_pool.user_pool_id
  group_name   = "admin"
  username     = aws_cognito_user.demo[0].username
}

# Argo CD bootstrap: namespace + Helm install
resource "kubernetes_namespace" "argocd" {
  metadata {
    name   = "argocd"
    labels = { name = "argocd" }
  }
  depends_on = [module.eks]
}

resource "helm_release" "argocd" {
  name             = "argo-cd"
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-cd"
  version          = "9.4.1"
  namespace        = kubernetes_namespace.argocd.metadata[0].name
  create_namespace = false
  values = [
    yamlencode({
      configs = {
        params = {
          "server.insecure" = "true"
          "server.url"      = "https://${local.argocd_host}"
        }
        cm = merge(
          {
            url = "https://${local.argocd_host}"
          },
          {
            "oidc.config" = <<-EOT
              name: Cognito
              issuer: https://${module.cognito_user_pool.user_pool_endpoint}
              clientId: ${module.cognito_user_pool.client_ids[local.cognito_domain_prefix]}
              requestedScopes: ["openid", "profile", "email"]
              groupsClaim: "cognito:groups"
              logoutURL: "https://${module.cognito_user_pool.domain_name}.auth.${var.region}.amazoncognito.com/logout?client_id=${module.cognito_user_pool.client_ids[local.cognito_domain_prefix]}&logout_uri=${urlencode(local.argocd_base_url)}"
            EOT
          }
        )
        rbac = {
          "policy.default" = "role:readonly"
          "policy.csv"     = "g, argocd-admins, role:admin\ng, argocd-developers, role:readonly"
          scopes           = "[cognito:groups, email]"
        }
      }
    })
  ]

  depends_on = [kubernetes_namespace.argocd]
}

# External DNS: deployed by Argo CD (Application)
resource "kubernetes_manifest" "argocd_application_external_dns" {
  manifest = {
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata = {
      name      = "external-dns"
      namespace = kubernetes_namespace.argocd.metadata[0].name
    }
    spec = {
      project = "default"
      source = {
        repoURL        = "https://kubernetes-sigs.github.io/external-dns/"
        chart          = "external-dns"
        targetRevision = "1.20.0"
        helm = {
          values = <<-EOT
            provider:
              name: aws
            serviceAccount:
              create: true
            policy: sync
            logLevel: info
            logFormat: json
            txtOwnerId: ${var.cluster_name}
            domainFilters:
              - ${var.domain_name}
            extraArgs:
              aws-zone-type: public
            env:
              - name: AWS_DEFAULT_REGION
                value: ${var.region}
          EOT
        }
      }
      destination = {
        server    = "https://kubernetes.default.svc"
        namespace = "external-dns"
      }
      syncPolicy = {
        automated = {
          prune    = true
          selfHeal = true
        }
        syncOptions = ["CreateNamespace=true"]
      }
    }
  }
  depends_on = [helm_release.argocd]
}

# AWS Load Balancer Controller: deployed by Argo CD (Application)
resource "kubernetes_manifest" "argocd_application_aws_load_balancer_controller" {
  manifest = {
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata = {
      name      = "aws-load-balancer-controller"
      namespace = kubernetes_namespace.argocd.metadata[0].name
    }
    spec = {
      project = "default"
      source = {
        repoURL        = "https://aws.github.io/eks-charts"
        chart          = "aws-load-balancer-controller"
        targetRevision = "3.0.0"
        helm = {
          values = <<-EOT
            clusterName: ${var.cluster_name}
            serviceAccount:
              create: true
            region: ${var.region}
            vpcId: ${module.vpc.vpc_id}
            createIngressClassResource: true
            ingressClass: alb
            enableServiceMutatorWebhook: false
            enableShield: false
            enableWaf: false
            enableWafv2: false
          EOT
        }
      }
      destination = {
        server    = "https://kubernetes.default.svc"
        namespace = "aws-load-balancer-controller"
      }
      syncPolicy = {
        automated = {
          prune    = true
          selfHeal = true
        }
        syncOptions = ["CreateNamespace=true"]
      }
    }
  }
  depends_on = [helm_release.argocd]
}

# Argo CD ingress (config is in helm_release values above)
resource "kubernetes_ingress_v1" "argocd_server" {
  count = var.certificate_arn != "" ? 1 : 0

  metadata {
    name      = "argocd-server-ingress"
    namespace = kubernetes_namespace.argocd.metadata[0].name
    annotations = {
      "alb.ingress.kubernetes.io/group.name"                   = "default-public-ingress"
      "alb.ingress.kubernetes.io/scheme"                       = "internet-facing"
      "alb.ingress.kubernetes.io/target-type"                  = "ip"
      "alb.ingress.kubernetes.io/listen-ports"                 = "[{\"HTTP\": 80}, {\"HTTPS\": 443}]"
      "alb.ingress.kubernetes.io/ssl-redirect"                 = "443"
      "alb.ingress.kubernetes.io/certificate-arn"              = var.certificate_arn
      "external-dns.alpha.kubernetes.io/hostname"              = local.argocd_host
      "alb.ingress.kubernetes.io/healthcheck-path"             = "/healthz"
      "alb.ingress.kubernetes.io/healthcheck-protocol"         = "HTTP"
      "alb.ingress.kubernetes.io/healthcheck-interval-seconds" = "15"
      "alb.ingress.kubernetes.io/healthcheck-timeout-seconds"  = "5"
      "alb.ingress.kubernetes.io/healthy-threshold-count"      = "2"
      "alb.ingress.kubernetes.io/unhealthy-threshold-count"    = "2"
      "alb.ingress.kubernetes.io/healthcheck-matcher"          = "200-399"
    }
  }
  spec {
    ingress_class_name = "alb"
    rule {
      host = local.argocd_host
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = "argo-cd-argocd-server"
              port {
                number = 80
              }
            }
          }
        }
      }
    }
  }
  depends_on = [helm_release.argocd]
}
