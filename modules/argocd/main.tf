resource "helm_release" "argocd" {
  name             = "argocd"
  namespace        = var.namespace
  create_namespace = true
  repository       = "https://k8sforge.github.io/argocd-chart"
  chart            = "argocd"
  version          = var.chart_version

  wait      = true
  skip_crds = true # Skip CRDs to reduce release manifest size (avoids "Request entity too large" error)

  values = [
    yamlencode({
      argocd = {
        enabled = true
      }
      "argo-cd" = {
        server = {
          service = {
            type = "ClusterIP"
            port = 80
          }
          insecure = true
          # Configure ArgoCD to serve from subpath
          rootpath = var.argocd_path_prefix
          basehref = var.argocd_path_prefix
          # Additional server configuration for subpath
          extraArgs = [
            "--rootpath=${var.argocd_path_prefix}",
            "--basehref=${var.argocd_path_prefix}"
          ]
        }
        configs = {
          params = {
            "server.insecure" = "true"
            "server.rootpath" = var.argocd_path_prefix
            "server.basehref" = var.argocd_path_prefix
            # Set the URL to help ArgoCD generate correct basehref
            "server.url" = var.enable_https ? "https://${var.platform_domain}${var.argocd_path_prefix}" : "http://${var.platform_domain}${var.argocd_path_prefix}"
          }
        }
      }
      ingress = {
        enabled = false # Disable ingress in helm chart - we'll create a dedicated ingress resource
      }
      healthCheck = {
        enabled  = true
        path     = "/healthz"
        protocol = "HTTP"
        port     = "traffic-port"
      }
      rollouts = {
        enabled = true # Installs Argo Rollouts controller and configures ArgoCD support
      }
      "argo-rollouts" = {
        # Argo Rollouts controller configuration
        # Leave empty for defaults, or add custom values here
      }
    })
  ]
}

# Read the ArgoCD admin credentials from the Kubernetes secret
data "kubernetes_secret" "argocd_admin" {
  metadata {
    name      = "argocd-initial-admin-secret"
    namespace = var.namespace
  }

  depends_on = [helm_release.argocd]
}

# Dedicated Ingress resource for ArgoCD using shared ALB
resource "kubernetes_ingress_v1" "argocd" {
  metadata {
    name      = "argocd-server"
    namespace = var.namespace
    annotations = merge(
      {
        "alb.ingress.kubernetes.io/scheme"           = "internet-facing"
        "alb.ingress.kubernetes.io/target-type"      = "ip"
        "alb.ingress.kubernetes.io/subnets"          = join(",", var.subnet_ids)
        "alb.ingress.kubernetes.io/backend-protocol" = "HTTP"
        "alb.ingress.kubernetes.io/healthcheck-path" = "${var.argocd_path_prefix}/healthz"
        "alb.ingress.kubernetes.io/group.name"       = var.shared_alb_ingress_group_name
      },
      # Security group for IP restrictions (if provided)
      var.shared_alb_security_group_id != "" ? {
        "alb.ingress.kubernetes.io/security-groups" = var.shared_alb_security_group_id
      } : {},
      # HTTP-only configuration
      !var.enable_https ? {
        "alb.ingress.kubernetes.io/listen-ports" = "[{\"HTTP\": 80}]"
      } : {},
      # HTTPS configuration (base)
      var.enable_https ? {
        "alb.ingress.kubernetes.io/listen-ports"    = "[{\"HTTP\": 80}, {\"HTTPS\": 443}]"
        "alb.ingress.kubernetes.io/certificate-arn" = var.certificate_arn
        "alb.ingress.kubernetes.io/ssl-policy"      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
      } : {},
      # HTTPS redirect (optional)
      var.enable_https && var.ssl_redirect ? {
        "alb.ingress.kubernetes.io/ssl-redirect" = "443"
      } : {}
    )
  }

  spec {
    ingress_class_name = "alb"

    rule {
      http {
        # Health check path - ArgoCD serves /healthz regardless of rootpath
        path {
          path      = "/healthz"
          path_type = "Exact"
          backend {
            service {
              name = "argocd-server"
              port {
                number = 80
              }
            }
          }
        }
        # Main ArgoCD path
        path {
          path      = var.argocd_path_prefix
          path_type = "Prefix"
          backend {
            service {
              name = "argocd-server"
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

# Kubernetes Secret for Cognito Client Secret
resource "kubernetes_secret" "cognito_client_secret" {
  count = var.enable_cognito_oidc ? 1 : 0

  metadata {
    name      = "cognito-client-secret"
    namespace = var.namespace
  }

  data = {
    client-secret = var.cognito_user_pool_client_secret
  }

  type = "Opaque"

  depends_on = [helm_release.argocd]
}

# Patch the ArgoCD ConfigMap to set correct URL and OIDC configuration
# The Helm chart doesn't always apply these values correctly
# Use force=true to override Helm's field management
resource "kubernetes_config_map_v1_data" "argocd_cm_patch" {
  metadata {
    name      = "argocd-cm"
    namespace = var.namespace
  }

  force = true

  data = merge(
    {
      url = var.enable_https ? "https://${var.platform_domain}${var.argocd_path_prefix}" : "http://${var.platform_domain}${var.argocd_path_prefix}"
    },
    # Add OIDC configuration if Cognito is enabled
    var.enable_cognito_oidc ? {
      # ArgoCD OIDC configuration format
      "oidc.config" = <<-EOT
name: Cognito
issuer: ${var.cognito_oidc_issuer_url}
clientId: ${var.cognito_user_pool_client_id}
# Note: clientSecret is not needed for public clients (browser-based OIDC flows)
requestedScopes: ["openid", "profile", "email"]
      EOT
    } : {}
  )

  depends_on = [
    helm_release.argocd,
    kubernetes_secret.cognito_client_secret
  ]
}

# Read RBAC policy from CSV file
locals {
  rbac_policy_file = var.rbac_policy_file != "" ? var.rbac_policy_file : "${path.module}/external/rbac-policy.csv"
  rbac_policy_csv  = fileexists(local.rbac_policy_file) ? file(local.rbac_policy_file) : ""
}

# ArgoCD RBAC ConfigMap - Configure RBAC policies with Cognito group mappings
resource "kubernetes_config_map_v1_data" "argocd_rbac_cm" {
  count = var.enable_cognito_oidc ? 1 : 0

  metadata {
    name      = "argocd-rbac-cm"
    namespace = var.namespace
  }

  force = true

  data = {
    # Default policy - conservative access (read-only)
    "policy.default" = "role:readonly"

    # Policy CSV - Loaded from external CSV file for easy maintenance
    # Remove comments and empty lines from CSV file
    "policy.csv" = join("\n", [
      for line in split("\n", local.rbac_policy_csv) :
      trimspace(line) if length(trimspace(line)) > 0 && !startswith(trimspace(line), "#")
    ])

    # Scopes to read from OIDC token
    scopes = "[groups, email]"
  }

  depends_on = [helm_release.argocd]
}

# Get the ArgoCD server Ingress to retrieve the ALB endpoint
data "kubernetes_ingress_v1" "argocd_server" {
  metadata {
    name      = "argocd-server"
    namespace = var.namespace
  }

  depends_on = [kubernetes_ingress_v1.argocd]
}
