data "aws_route53_zone" "this" {
  name         = var.domain_name
  private_zone = false
}

resource "aws_route53_record" "this" {
  count = var.alb_dns_name != "" && var.alb_zone_id != "" ? 1 : 0

  zone_id = data.aws_route53_zone.this.zone_id
  name    = "${var.name}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}
