data "aws_vpc" "this" {
  id = var.vpc_id
}

data "aws_lbs" "shared_alb" {
  tags = {
    "elbv2.k8s.aws/cluster" = var.cluster_name
    "ingress.k8s.aws/stack" = var.shared_alb_ingress_group_name
  }
}

locals {
  shared_alb_arns_list = length(data.aws_lbs.shared_alb.arns) > 0 ? try(
    tolist(data.aws_lbs.shared_alb.arns),
    []
  ) : []
}

data "aws_lb" "shared_alb_details" {
  count = length(local.shared_alb_arns_list) > 0 ? 1 : 0

  arn = local.shared_alb_arns_list[0]

  depends_on = [
    data.aws_lbs.shared_alb
  ]
}

locals {
  alb_arn = try(data.aws_lb.shared_alb_details[0].arn != "" ? data.aws_lb.shared_alb_details[0].arn : "", "")

  shared_alb_allowed_cidrs = length(var.shared_alb_allowed_ips) > 0 ? distinct(concat(
    [data.aws_vpc.this.cidr_block],
    var.shared_alb_allowed_ips
  )) : []
}

resource "aws_security_group" "shared_alb" {
  count = length(var.shared_alb_allowed_ips) > 0 ? 1 : 0

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

resource "aws_security_group_rule" "shared_alb_http_ingress" {
  count = length(var.shared_alb_allowed_ips) > 0 ? 1 : 0

  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = local.shared_alb_allowed_cidrs
  security_group_id = aws_security_group.shared_alb[0].id
  description       = "Allow HTTP from VPC CIDR and allowed IPs"
}

resource "aws_security_group_rule" "shared_alb_https_ingress" {
  count = length(var.shared_alb_allowed_ips) > 0 ? 1 : 0

  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = local.shared_alb_allowed_cidrs
  security_group_id = aws_security_group.shared_alb[0].id
  description       = "Allow HTTPS from VPC CIDR and allowed IPs"
}

resource "aws_security_group_rule" "shared_alb_egress" {
  count = length(var.shared_alb_allowed_ips) > 0 ? 1 : 0

  type              = "egress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.shared_alb[0].id
  description       = "Allow all outbound traffic"
}

data "aws_security_groups" "node_security_groups" {
  count = length(var.shared_alb_allowed_ips) > 0 ? 1 : 0

  filter {
    name   = "tag:kubernetes.io/cluster/${var.cluster_name}"
    values = ["owned"]
  }

  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }
}

resource "aws_security_group_rule" "node_from_alb" {
  for_each = length(var.shared_alb_allowed_ips) > 0 && length(data.aws_security_groups.node_security_groups) > 0 ? toset(data.aws_security_groups.node_security_groups[0].ids) : toset([])

  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.shared_alb[0].id
  security_group_id        = each.value
  description              = "Allow traffic from shared ALB security group to nodes"

  lifecycle {
    create_before_destroy = false
  }
}
