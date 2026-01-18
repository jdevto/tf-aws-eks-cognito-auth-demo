# Get current AWS region
data "aws_region" "current" {}

# Get VPC CIDR for health check rules
data "aws_vpc" "this" {
  id = var.vpc_id
}

# =============================================================================
# EKS (native resources)
# =============================================================================

# Cluster IAM role
data "aws_iam_policy_document" "eks_cluster_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "eks_cluster" {
  name               = "${var.cluster_name}-eks-cluster-role"
  assume_role_policy = data.aws_iam_policy_document.eks_cluster_assume_role.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# Node IAM role
data "aws_iam_policy_document" "eks_nodes_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "eks_nodes" {
  name               = "${var.cluster_name}-eks-nodes-role"
  assume_role_policy = data.aws_iam_policy_document.eks_nodes_assume_role.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "eks_nodes_worker" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_nodes_cni" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks_nodes_ecr" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# EKS control plane
resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  version  = var.cluster_version
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_public_access  = var.endpoint_public_access
    endpoint_private_access = true
    # Restrict public endpoint access to specific CIDRs (optional but recommended for security)
    public_access_cidrs = var.public_access_cidrs
  }

  # Enable control plane logging for audit and troubleshooting
  enabled_cluster_log_types = var.enabled_cluster_log_types

  tags = var.tags

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
  ]
}

# Managed node group
resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.cluster_name}-default"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = var.node_subnet_ids != null ? var.node_subnet_ids : var.subnet_ids

  instance_types = var.node_instance_types

  # Disk size configuration
  disk_size = var.node_disk_size

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  # Update configuration for rolling updates
  update_config {
    max_unavailable = var.node_update_max_unavailable
  }

  # Remote access configuration (SSH access control)
  dynamic "remote_access" {
    for_each = var.node_remote_access_enabled ? [1] : []
    content {
      ec2_ssh_key               = var.node_remote_access_ssh_key
      source_security_group_ids = var.node_remote_access_security_groups
    }
  }

  # Node labels (taints should be applied via Kubernetes, not at node group level)
  labels = var.node_labels

  tags = var.tags

  depends_on = [
    aws_iam_role_policy_attachment.eks_nodes_worker,
    aws_iam_role_policy_attachment.eks_nodes_cni,
    aws_iam_role_policy_attachment.eks_nodes_ecr,
  ]
}

# =============================================================================
# AWS Auth ConfigMap
# Maps IAM users and roles to Kubernetes RBAC groups
# Automatically includes the node group role so worker nodes can authenticate
# =============================================================================

locals {
  # Always include the node group role for worker node authentication
  node_group_role = {
    rolearn  = aws_iam_role.eks_nodes.arn
    username = "system:node:{{EC2PrivateDNSName}}"
    groups = [
      "system:bootstrappers",
      "system:nodes"
    ]
  }

  # Combine node group role with user-provided roles
  all_map_roles = concat([local.node_group_role], var.aws_auth_map_roles)
}

# AWS Auth ConfigMap - EKS creates this automatically, we only manage the data
# Using kubernetes_config_map_v1_data to update the existing configmap created by EKS
resource "kubernetes_config_map_v1_data" "aws_auth" {
  count = length(var.aws_auth_map_users) > 0 || length(var.aws_auth_map_roles) > 0 || true ? 1 : 0

  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  data = {
    mapUsers = length(var.aws_auth_map_users) > 0 ? yamlencode(var.aws_auth_map_users) : yamlencode([])
    mapRoles = yamlencode(local.all_map_roles)
  }

  # Force override field manager conflicts (EKS or other clients may be managing this)
  force = true

  depends_on = [
    aws_eks_cluster.this,
    aws_eks_node_group.default
  ]

  # Force replacement if the configmap doesn't exist yet (first time)
  lifecycle {
    replace_triggered_by = [
      aws_eks_node_group.default.id
    ]
  }
}

# =============================================================================
# EBS CSI Driver IAM (IRSA setup)
# =============================================================================

# IAM role for EBS CSI Driver
data "aws_iam_policy_document" "ebs_csi_driver_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }

    actions = ["sts:AssumeRoleWithWebIdentity"]

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ebs_csi_driver" {
  count = var.enable_ebs_csi_driver ? 1 : 0

  name               = "${var.cluster_name}-ebs-csi-driver"
  assume_role_policy = data.aws_iam_policy_document.ebs_csi_driver_assume_role.json
  tags               = var.tags
}

# Custom least-privilege IAM policy for EBS CSI Driver
resource "aws_iam_role_policy" "ebs_csi_driver" {
  count = var.enable_ebs_csi_driver ? 1 : 0

  name = "${var.cluster_name}-ebs-csi-driver-policy"
  role = aws_iam_role.ebs_csi_driver[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EBSCSIVolumeManagement"
        Effect = "Allow"
        Action = [
          "ec2:CreateVolume",
          "ec2:DeleteVolume",
          "ec2:AttachVolume",
          "ec2:DetachVolume",
          "ec2:ModifyVolume"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.region
          }
        }
      },
      {
        Sid    = "EBSCSISnapshotManagement"
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:DeleteSnapshot"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.region
          }
        }
      },
      {
        Sid    = "EBSCSIDescribeOperations"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSnapshots",
          "ec2:DescribeVolumes",
          "ec2:DescribeAvailabilityZones"
        ]
        Resource = "*"
      },
      {
        Sid    = "EBSCSITaggingOperations"
        Effect = "Allow"
        Action = [
          "ec2:CreateTags",
          "ec2:DescribeTags"
        ]
        Resource = [
          "arn:aws:ec2:*:*:volume/*",
          "arn:aws:ec2:*:*:snapshot/*"
        ]
        Condition = {
          StringEquals = {
            "ec2:CreateAction" = [
              "CreateVolume",
              "CreateSnapshot"
            ]
          }
        }
      }
    ]
  })
}

# EBS CSI Driver Add-on
resource "aws_eks_addon" "ebs_csi_driver" {
  count = var.enable_ebs_csi_driver ? 1 : 0

  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "aws-ebs-csi-driver"
  addon_version               = var.ebs_csi_driver_version
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  service_account_role_arn    = aws_iam_role.ebs_csi_driver[0].arn

  depends_on = [
    aws_eks_node_group.default,
    aws_iam_role_policy.ebs_csi_driver[0]
  ]

  tags = var.tags
}

# Default StorageClass for EBS CSI Driver
resource "kubernetes_storage_class" "ebs_csi_default" {
  count = var.enable_ebs_csi_driver ? 1 : 0

  metadata {
    name = "gp3"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }

  storage_provisioner    = "ebs.csi.aws.com"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  parameters = {
    type   = "gp3"
    fsType = "ext4"
  }

  depends_on = [
    aws_eks_addon.ebs_csi_driver[0]
  ]
}

# =============================================================================
# AWS Load Balancer Controller IAM (IRSA setup)
# Note: Kubernetes resources are created at root level to avoid provider cycles
# =============================================================================

# OIDC provider for IRSA
data "tls_certificate" "eks" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer

  tags = var.tags
}

# IAM role for AWS Load Balancer Controller
data "aws_iam_policy_document" "aws_lb_controller_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }

    actions = ["sts:AssumeRoleWithWebIdentity"]

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-load-balancer-controller"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "aws_lb_controller" {
  name               = "${var.cluster_name}-aws-lb-controller"
  assume_role_policy = data.aws_iam_policy_document.aws_lb_controller_assume_role.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "aws_lb_controller" {
  role       = aws_iam_role.aws_lb_controller.name
  policy_arn = "arn:aws:iam::aws:policy/ElasticLoadBalancingFullAccess"
}

resource "aws_iam_role_policy_attachment" "aws_lb_controller_ec2" {
  role       = aws_iam_role.aws_lb_controller.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_role_policy" "aws_lb_controller_waf" {
  name = "${var.cluster_name}-aws-lb-controller-waf"
  role = aws_iam_role.aws_lb_controller.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WAFv2Permissions"
        Effect = "Allow"
        Action = [
          "wafv2:GetWebACL",
          "wafv2:GetWebACLForResource",
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL",
          "wafv2:ListWebACLs"
        ]
        Resource = "*"
      },
      {
        Sid    = "WAFRegionalPermissions"
        Effect = "Allow"
        Action = [
          "waf-regional:GetWebACL",
          "waf-regional:GetWebACLForResource",
          "waf-regional:AssociateWebACL",
          "waf-regional:DisassociateWebACL",
          "waf-regional:ListWebACLs"
        ]
        Resource = "*"
      },
      {
        Sid    = "ShieldPermissions"
        Effect = "Allow"
        Action = [
          "shield:GetSubscriptionState",
          "shield:DescribeProtection",
          "shield:CreateProtection",
          "shield:DeleteProtection"
        ]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# AWS Load Balancer Controller Installation
# =============================================================================

# Kubernetes Service Account for AWS Load Balancer Controller
resource "kubernetes_service_account" "aws_lb_controller" {
  count = var.enable_aws_lb_controller ? 1 : 0

  metadata {
    name      = "aws-load-balancer-controller"
    namespace = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.aws_lb_controller.arn
    }
    labels = {
      "app.kubernetes.io/name"       = "aws-load-balancer-controller"
      "app.kubernetes.io/component"  = "controller"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  depends_on = [
    aws_eks_cluster.this,
    aws_eks_node_group.default,
    aws_iam_role_policy_attachment.aws_lb_controller,
    aws_iam_role_policy_attachment.aws_lb_controller_ec2,
    aws_iam_role_policy.aws_lb_controller_waf
  ]
}

# Helm Release for AWS Load Balancer Controller
resource "helm_release" "aws_load_balancer_controller" {
  count = var.enable_aws_lb_controller ? 1 : 0

  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"
  version    = var.aws_lb_controller_helm_version

  set {
    name  = "clusterName"
    value = aws_eks_cluster.this.name
  }

  set {
    name  = "serviceAccount.create"
    value = "false"
  }

  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }

  set {
    name  = "region"
    value = data.aws_region.current.region
  }

  set {
    name  = "vpcId"
    value = var.vpc_id
  }

  dynamic "set" {
    for_each = var.aws_lb_controller_helm_values
    content {
      name  = set.key
      value = set.value
    }
  }

  depends_on = [
    kubernetes_service_account.aws_lb_controller[0],
    aws_eks_node_group.default
  ]
}

data "aws_lbs" "shared_alb" {
  count = var.enable_shared_alb && var.shared_alb_ingress_group_name != "" ? 1 : 0

  tags = {
    "elbv2.k8s.aws/cluster" = aws_eks_cluster.this.name
    "ingress.k8s.aws/stack" = var.shared_alb_ingress_group_name
  }

  depends_on = [
    helm_release.aws_load_balancer_controller
  ]
}

locals {
  shared_alb_arns_list = var.enable_shared_alb && var.shared_alb_ingress_group_name != "" ? try(
    tolist(data.aws_lbs.shared_alb[0].arns),
    []
  ) : []
  shared_alb_arn = length(local.shared_alb_arns_list) > 0 ? local.shared_alb_arns_list[0] : ""

  # Use static key for for_each - key is known at plan time, value can be dynamic
  # Only include in map if we have a valid ARN (non-empty string)
  shared_alb_for_each_map = var.enable_shared_alb && var.shared_alb_ingress_group_name != "" && local.shared_alb_arn != "" ? {
    shared = local.shared_alb_arn
  } : {}

  # Merge VPC CIDR with allowed IPs
  # VPC CIDR is always included for internal ALB health checks and internal traffic
  # Remove duplicates in case user already included VPC CIDR in their allowed IPs
  shared_alb_allowed_cidrs = var.enable_shared_alb && length(var.shared_alb_allowed_ips) > 0 ? distinct(concat(
    [data.aws_vpc.this.cidr_block],
    var.shared_alb_allowed_ips
  )) : []
}

# Get ALB details - only query when we have a valid ARN
# Using name filter in addition to ARN to ensure uniqueness
data "aws_lb" "shared_alb_details" {
  for_each = local.shared_alb_for_each_map

  # Use ARN for precise lookup - this should be unique
  arn = each.value
}

# Query ALB listeners
# The ALB is created by AWS Load Balancer Controller
# Since there's no aws_lb_listeners data source, we use external data source to query via AWS CLI
locals {
  alb_arn_for_query = var.enable_shared_alb && try(data.aws_lb.shared_alb_details["shared"].arn != "", false) ? data.aws_lb.shared_alb_details["shared"].arn : ""
}

data "external" "alb_listeners" {
  count = local.alb_arn_for_query != "" ? 1 : 0

  program = ["bash", "-c", <<-EOT
    # Read JSON from stdin
    QUERY=$(cat)
    ALB_ARN=$(echo "$QUERY" | jq -r '.alb_arn // empty')

    if [ -z "$ALB_ARN" ]; then
      echo '{}'
      exit 0
    fi

    # Query listeners and extract ARNs by port
    RESULT=$(aws elbv2 describe-listeners \
      --load-balancer-arn "$ALB_ARN" \
      --query 'Listeners[*].[ListenerArn,Port]' \
      --output json 2>/dev/null)

    if [ $? -eq 0 ] && [ -n "$RESULT" ] && [ "$RESULT" != "null" ] && [ "$RESULT" != "[]" ]; then
      # Use jq to format as {port: arn} map, handle empty arrays
      echo "$RESULT" | jq -c 'if type == "array" and length > 0 then map({port: (.[1] | tostring), arn: .[0]}) | from_entries else {} end' 2>/dev/null || echo '{}'
    else
      echo '{}'
    fi
  EOT
  ]

  query = {
    alb_arn = local.alb_arn_for_query
  }

  depends_on = [
    data.aws_lb.shared_alb_details
  ]
}

# Extract HTTP and HTTPS listener ARNs from external data
locals {
  # HTTP listener ARN (port 80)
  http_listener_arn = length(data.external.alb_listeners) > 0 ? try(
    jsondecode(data.external.alb_listeners[0].result)["80"]["arn"],
    ""
  ) : ""

  # HTTPS listener ARN (port 443)
  https_listener_arn = length(data.external.alb_listeners) > 0 ? try(
    jsondecode(data.external.alb_listeners[0].result)["443"]["arn"],
    ""
  ) : ""
}

# =============================================================================
# Security Group for Shared ALB
# Restricts access to allowed IPs when shared_alb_allowed_ips is configured
# =============================================================================

resource "aws_security_group" "shared_alb" {
  count = var.enable_shared_alb && length(var.shared_alb_allowed_ips) > 0 ? 1 : 0

  name        = "${var.cluster_name}-shared-alb"
  description = "Security group for shared ALB with IP restrictions"
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-shared-alb"
    }
  )
}

# Allow HTTP from VPC CIDR + allowed IPs
resource "aws_security_group_rule" "shared_alb_http_ingress" {
  count = var.enable_shared_alb && length(var.shared_alb_allowed_ips) > 0 ? 1 : 0

  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = local.shared_alb_allowed_cidrs
  security_group_id = aws_security_group.shared_alb[0].id
  description       = "Allow HTTP from VPC CIDR and allowed IPs"
}

# Allow HTTPS from VPC CIDR + allowed IPs
resource "aws_security_group_rule" "shared_alb_https_ingress" {
  count = var.enable_shared_alb && length(var.shared_alb_allowed_ips) > 0 ? 1 : 0

  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = local.shared_alb_allowed_cidrs
  security_group_id = aws_security_group.shared_alb[0].id
  description       = "Allow HTTPS from VPC CIDR and allowed IPs"
}

# Allow all outbound traffic (for health checks and backend communication)
resource "aws_security_group_rule" "shared_alb_egress" {
  count = var.enable_shared_alb && length(var.shared_alb_allowed_ips) > 0 ? 1 : 0

  type              = "egress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.shared_alb[0].id
  description       = "Allow all outbound traffic"
}

# =============================================================================
# Allow ALB to communicate with nodes
# When using a custom ALB security group, we need to ensure nodes allow
# traffic from the ALB security group for health checks and backend traffic
# =============================================================================

# Get the node security group from the node group
# EKS automatically creates security groups for node groups
# Query for all security groups owned by the cluster in the VPC
data "aws_security_groups" "node_security_groups" {
  count = var.enable_shared_alb && length(var.shared_alb_allowed_ips) > 0 ? 1 : 0

  filter {
    name   = "tag:kubernetes.io/cluster/${var.cluster_name}"
    values = ["owned"]
  }

  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }

  depends_on = [aws_eks_node_group.default]
}

# Allow traffic from ALB security group to node security groups
# This allows the ALB to perform health checks and forward traffic to pods
# Note: We allow all TCP ports (0-65535) to cover all possible service ports
#
# IMPORTANT: This requires the node group security groups to exist.
# This typically requires two Terraform applies:
# 1. First apply: Creates node group (security groups may not be discoverable yet)
# 2. Second apply: Creates these security group rules once security groups are known
#
# Alternative: Use terraform apply -target=aws_eks_node_group.default first, then full apply
resource "aws_security_group_rule" "node_from_alb" {
  # Only create when we have security groups (non-empty list)
  # Use the actual length of the security groups list, capped at 5 for safety
  # This will be 0 if the list is empty or unknown, effectively skipping creation
  count = var.enable_shared_alb && length(var.shared_alb_allowed_ips) > 0 && try(
    length(data.aws_security_groups.node_security_groups[0].ids) > 0,
    false
  ) ? min(try(length(data.aws_security_groups.node_security_groups[0].ids), 0), 5) : 0

  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.shared_alb[0].id
  security_group_id        = data.aws_security_groups.node_security_groups[0].ids[count.index]
  description              = "Allow traffic from shared ALB security group to nodes"
}

# =============================================================================
# ALB Listener Rules with Cognito Authentication
# =============================================================================

# Data sources to get listener details
data "aws_lb_listener" "http_for_rules" {
  count = var.enable_shared_alb && var.enable_cognito_auth && local.http_listener_arn != "" ? 1 : 0
  arn   = local.http_listener_arn
}

data "aws_lb_listener" "https_for_rules" {
  count = var.enable_shared_alb && var.enable_cognito_auth && var.enable_https && local.https_listener_arn != "" ? 1 : 0
  arn   = local.https_listener_arn
}

# ALB Listener Rules for HTTP (port 80)
# Note: Lower priority numbers are evaluated FIRST in ALB
# These rules use priorities 1-4 to ensure they're evaluated before Load Balancer Controller rules

# Rule 1: /healthz - Public, no auth (Priority 1)
resource "aws_lb_listener_rule" "http_healthz" {
  count        = var.enable_shared_alb && var.enable_cognito_auth && local.http_listener_arn != "" ? 1 : 0
  listener_arn = local.http_listener_arn
  priority     = 1

  action {
    type             = "forward"
    target_group_arn = data.aws_lb_listener.http_for_rules[0].default_action[0].target_group_arn
  }

  condition {
    path_pattern {
      values = ["/healthz"]
    }
  }

  tags = var.tags
}

# Rule 2: /argocd/healthz - Public, no auth (Priority 2)
resource "aws_lb_listener_rule" "http_argocd_healthz" {
  count        = var.enable_shared_alb && var.enable_cognito_auth && local.http_listener_arn != "" ? 1 : 0
  listener_arn = local.http_listener_arn
  priority     = 2

  action {
    type             = "forward"
    target_group_arn = data.aws_lb_listener.http_for_rules[0].default_action[0].target_group_arn
  }

  condition {
    path_pattern {
      values = ["/argocd/healthz"]
    }
  }

  tags = var.tags
}

# Rule 3: / - Public, no auth (Priority 3)
resource "aws_lb_listener_rule" "http_root" {
  count        = var.enable_shared_alb && var.enable_cognito_auth && local.http_listener_arn != "" ? 1 : 0
  listener_arn = local.http_listener_arn
  priority     = 3

  action {
    type             = "forward"
    target_group_arn = data.aws_lb_listener.http_for_rules[0].default_action[0].target_group_arn
  }

  condition {
    path_pattern {
      values = ["/"]
    }
  }

  tags = var.tags
}

# Rule 4: /argocd/* - Protected, Cognito auth required (Priority 4)
resource "aws_lb_listener_rule" "http_argocd_protected" {
  count        = var.enable_shared_alb && var.enable_cognito_auth && local.http_listener_arn != "" ? 1 : 0
  listener_arn = local.http_listener_arn
  priority     = 4

  action {
    type = "authenticate-cognito"
    authenticate_cognito {
      user_pool_arn              = var.cognito_user_pool_arn
      user_pool_client_id        = var.cognito_user_pool_client_id
      user_pool_domain           = var.cognito_user_pool_domain
      on_unauthenticated_request = "authenticate"
      session_cookie_name        = "AWSELBAuthSessionCookie"
      session_timeout            = 604800 # 7 days
    }
  }

  action {
    type             = "forward"
    target_group_arn = data.aws_lb_listener.http_for_rules[0].default_action[0].target_group_arn
  }

  condition {
    path_pattern {
      values = ["/argocd/*"]
    }
  }

  tags = var.tags
}

# ALB Listener Rules for HTTPS (port 443) - only if HTTPS is enabled
# Rule 1: /healthz - Public, no auth (Priority 1)
resource "aws_lb_listener_rule" "https_healthz" {
  count        = var.enable_shared_alb && var.enable_cognito_auth && var.enable_https && local.https_listener_arn != "" ? 1 : 0
  listener_arn = local.https_listener_arn
  priority     = 1

  action {
    type             = "forward"
    target_group_arn = data.aws_lb_listener.https_for_rules[0].default_action[0].target_group_arn
  }

  condition {
    path_pattern {
      values = ["/healthz"]
    }
  }

  tags = var.tags
}

# Rule 2: /argocd/healthz - Public, no auth (Priority 2)
resource "aws_lb_listener_rule" "https_argocd_healthz" {
  count        = var.enable_shared_alb && var.enable_cognito_auth && var.enable_https && local.https_listener_arn != "" ? 1 : 0
  listener_arn = local.https_listener_arn
  priority     = 2

  action {
    type             = "forward"
    target_group_arn = data.aws_lb_listener.https_for_rules[0].default_action[0].target_group_arn
  }

  condition {
    path_pattern {
      values = ["/argocd/healthz"]
    }
  }

  tags = var.tags
}

# Rule 3: / - Public, no auth (Priority 3)
resource "aws_lb_listener_rule" "https_root" {
  count        = var.enable_shared_alb && var.enable_cognito_auth && var.enable_https && local.https_listener_arn != "" ? 1 : 0
  listener_arn = local.https_listener_arn
  priority     = 3

  action {
    type             = "forward"
    target_group_arn = data.aws_lb_listener.https_for_rules[0].default_action[0].target_group_arn
  }

  condition {
    path_pattern {
      values = ["/"]
    }
  }

  tags = var.tags
}

# Rule 4: /argocd/* - Protected, Cognito auth required (Priority 4)
resource "aws_lb_listener_rule" "https_argocd_protected" {
  count        = var.enable_shared_alb && var.enable_cognito_auth && var.enable_https && local.https_listener_arn != "" ? 1 : 0
  listener_arn = local.https_listener_arn
  priority     = 4

  action {
    type = "authenticate-cognito"
    authenticate_cognito {
      user_pool_arn              = var.cognito_user_pool_arn
      user_pool_client_id        = var.cognito_user_pool_client_id
      user_pool_domain           = var.cognito_user_pool_domain
      on_unauthenticated_request = "authenticate"
      session_cookie_name        = "AWSELBAuthSessionCookie"
      session_timeout            = 604800 # 7 days
    }
  }

  action {
    type             = "forward"
    target_group_arn = data.aws_lb_listener.https_for_rules[0].default_action[0].target_group_arn
  }

  condition {
    path_pattern {
      values = ["/argocd/*"]
    }
  }

  tags = var.tags
}
