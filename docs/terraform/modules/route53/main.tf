resource "aws_route53_zone" "main" {
  count = var.create_zone ? 1 : 0
  name  = var.domain_name

  tags = {
    Name        = "${var.project}-${var.environment}-zone"
    Environment = var.environment
    Project     = var.project
  }
}

resource "aws_route53_record" "main" {
  zone_id = var.create_zone ? aws_route53_zone.main[0].zone_id : var.hosted_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id               = var.alb_zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "www" {
  zone_id = var.create_zone ? aws_route53_zone.main[0].zone_id : var.hosted_zone_id
  name    = "www.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id               = var.alb_zone_id
    evaluate_target_health = true
  }
}
