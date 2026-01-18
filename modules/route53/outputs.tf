output "custom_domain" {
  description = "Custom domain FQDN"
  value       = length(aws_route53_record.this) > 0 ? aws_route53_record.this[0].fqdn : ""
}
