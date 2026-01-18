locals {
  rbac_policy_file = var.rbac_policy_file != "" ? var.rbac_policy_file : "${path.module}/external/rbac-policy.csv"
  rbac_policy_csv  = fileexists(local.rbac_policy_file) ? file(local.rbac_policy_file) : ""

  rbac_policy_processed = join("\n", [
    for line in split("\n", local.rbac_policy_csv) :
    trimspace(line) if length(trimspace(line)) > 0 && !startswith(trimspace(line), "#")
  ])
}

resource "helm_release" "argocd" {
  name             = "argocd"
  namespace        = var.namespace
  create_namespace = true
  repository       = "https://k8sforge.github.io/argocd-chart"
  chart            = "argocd"
  version          = var.chart_version

  wait      = true
  skip_crds = true

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
          rootpath = var.argocd_path_prefix
          basehref = var.argocd_path_prefix
          extraArgs = [
            "--rootpath=${var.argocd_path_prefix}",
            "--basehref=${var.argocd_path_prefix}"
          ]
        }
        configs = merge(
          {
            params = {
              "server.insecure" = "true"
              "server.rootpath" = var.argocd_path_prefix
              "server.basehref" = var.argocd_path_prefix
              "server.url"      = var.enable_https ? "https://${var.platform_domain}${var.argocd_path_prefix}" : "http://${var.platform_domain}${var.argocd_path_prefix}"
            }
            cm = merge(
              {
                url = var.enable_https ? "https://${var.platform_domain}${var.argocd_path_prefix}" : "http://${var.platform_domain}${var.argocd_path_prefix}"
              },
              var.enable_cognito_oidc ? {
                "oidc.config" = <<-EOT
name: Cognito
issuer: ${var.cognito_oidc_issuer_url}
clientId: ${var.cognito_user_pool_client_id}
requestedScopes: ["openid", "profile", "email"]
${var.cognito_user_pool_domain_url != "" ? "logoutURL: \"${var.cognito_user_pool_domain_url}/logout?client_id=${var.cognito_user_pool_client_id}&logout_uri=${urlencode("https://${var.platform_domain}${var.argocd_path_prefix}")}\"" : ""}
                EOT
              } : {}
            )
          },
          var.enable_cognito_oidc ? {
            rbac = {
              "policy.default" = "role:readonly"
              "policy.csv"     = local.rbac_policy_processed
              scopes           = "[groups, email]"
            }
          } : {}
        )
      }
      ingress = {
        enabled = false
      }
      healthCheck = {
        enabled  = true
        path     = "/healthz"
        protocol = "HTTP"
        port     = "traffic-port"
      }
      rollouts = {
        enabled = true
      }
      "argo-rollouts" = {}
    })
  ]
}

data "kubernetes_secret" "argocd_admin" {
  metadata {
    name      = "argocd-initial-admin-secret"
    namespace = var.namespace
  }

  depends_on = [helm_release.argocd]
}

resource "kubernetes_ingress_v1" "argocd" {
  metadata {
    name      = "argocd-server"
    namespace = var.namespace
    annotations = merge(
      {
        "alb.ingress.kubernetes.io/scheme"                   = "internet-facing"
        "alb.ingress.kubernetes.io/target-type"              = "ip"
        "alb.ingress.kubernetes.io/subnets"                  = join(",", var.subnet_ids)
        "alb.ingress.kubernetes.io/backend-protocol"         = "HTTP"
        "alb.ingress.kubernetes.io/healthcheck-path"         = "${var.argocd_path_prefix}/healthz"
        "alb.ingress.kubernetes.io/group.name"               = var.shared_alb_ingress_group_name
        "alb.ingress.kubernetes.io/load-balancer-attributes" = "idle_timeout.timeout_seconds=3600"
      },
      var.shared_alb_security_group_id != "" ? {
        "alb.ingress.kubernetes.io/security-groups" = var.shared_alb_security_group_id
      } : {},
      !var.enable_https ? {
        "alb.ingress.kubernetes.io/listen-ports" = "[{\"HTTP\": 80}]"
      } : {},
      var.enable_https ? {
        "alb.ingress.kubernetes.io/listen-ports"    = "[{\"HTTP\": 80}, {\"HTTPS\": 443}]"
        "alb.ingress.kubernetes.io/certificate-arn" = var.certificate_arn
        "alb.ingress.kubernetes.io/ssl-policy"      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
      } : {},
      var.enable_https && var.ssl_redirect ? {
        "alb.ingress.kubernetes.io/ssl-redirect" = "443"
      } : {}
    )
  }

  spec {
    ingress_class_name = "alb"

    rule {
      http {
        path {
          path      = "${var.argocd_path_prefix}/healthz"
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

resource "kubernetes_config_map_v1_data" "argocd_cm_patch" {
  count = var.enable_cognito_oidc ? 1 : 0

  metadata {
    name      = "argocd-cm"
    namespace = var.namespace
  }

  force = true

  data = {
    url           = var.enable_https ? "https://${var.platform_domain}${var.argocd_path_prefix}" : "http://${var.platform_domain}${var.argocd_path_prefix}"
    "oidc.config" = <<-EOT
name: Cognito
issuer: ${var.cognito_oidc_issuer_url}
clientId: ${var.cognito_user_pool_client_id}
requestedScopes: ["openid", "profile", "email"]
${var.cognito_user_pool_domain_url != "" ? "logoutURL: \"${var.cognito_user_pool_domain_url}/logout?client_id=${var.cognito_user_pool_client_id}&logout_uri=${urlencode("https://${var.platform_domain}${var.argocd_path_prefix}")}\"" : ""}
    EOT
  }

  depends_on = [helm_release.argocd]

  lifecycle {
    ignore_changes = all
  }
}

resource "kubernetes_config_map_v1_data" "argocd_rbac_cm" {
  count = var.enable_cognito_oidc ? 1 : 0

  metadata {
    name      = "argocd-rbac-cm"
    namespace = var.namespace
  }

  force = true

  data = {
    "policy.default" = "role:readonly"
    "policy.csv"     = local.rbac_policy_processed
    scopes           = "[groups, email]"
  }

  depends_on = [helm_release.argocd]

  lifecycle {
    ignore_changes = all
  }
}

data "kubernetes_ingress_v1" "argocd_server" {
  metadata {
    name      = "argocd-server"
    namespace = var.namespace
  }

  depends_on = [kubernetes_ingress_v1.argocd]
}
