terraform {
  required_version = "= 1.16.1"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.63.0"
    }
  }
  backend "s3" {
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = { Application = "redsim", Environment = var.environment, ManagedBy = "terraform" }
  }
}
variable "account_id" { type = string }
variable "environment" { type = string }
variable "state_bucket" { type = string }
variable "fqdn" { type = string }
variable "hosted_zone_id" { type = string }
variable "images" {
  description = "Verified ECR digest references, including the realm-configured identity image."
  type        = map(string)
  validation {
    condition = alltrue([for name in ["api", "web", "worker", "identity"] :
      can(regex("^[0-9]{12}\\.dkr\\.ecr\\.us-east-1\\.amazonaws\\.com/ndia-red-team/[a-z-]+@sha256:[a-f0-9]{64}$", var.images[name]))
    ])
    error_message = "Provide immutable same-region ECR digest references for every image family."
  }
}
variable "service_secrets" {
  description = "Environment name to Secrets Manager valueFrom reference by service; values never enter Terraform."
  type        = map(map(string))
  validation {
    condition = alltrue(flatten([for entries in values(var.service_secrets) : [
      for ref in values(entries) : can(regex("^arn:aws:secretsmanager:us-east-1:${var.account_id}:secret:[A-Za-z0-9/_+=.@!-]+:[A-Za-z0-9_]+::$", ref))
    ]]))
    error_message = "Use same-account Secrets Manager JSON-key references, never credential values."
  }
}
variable "enable_services" {
  description = "Enable only after the migration task has exited successfully."
  type        = bool
  default     = false
}
variable "enable_workers" {
  description = "Enable only after a validated asset bundle is available in S3."
  type        = bool
  default     = false
}

variable "asset_bundle" {
  description = "Operator-built S3 archive pinned by its content hash; required before ML workers start."
  type        = object({ key = string, sha256 = string })
  default     = null
  validation {
    condition = var.asset_bundle == null ? true : (
      can(regex("^[a-f0-9]{64}$", var.asset_bundle.sha256)) &&
      var.asset_bundle.key == "assets/bundles/${var.asset_bundle.sha256}.tar.gz"
    )
    error_message = "Use the content-addressed bundle key emitted by upload_assets.py."
  }
}

data "terraform_remote_state" "foundation" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "foundation/terraform.tfstate"
    region = "us-east-1"
  }
}
locals {
  foundation = data.terraform_remote_state.foundation.outputs
  network    = local.foundation.foundation_network
  database   = local.foundation.data_connections.database
  redis      = local.foundation.data_connections.redis
  name       = "ndia-red-team-${var.environment}"
  origin     = "https://${var.fqdn}"
}

data "aws_lb" "foundation" { arn = local.network.alb_arn }
data "aws_security_group" "alb" {
  name   = "${local.name}-alb"
  vpc_id = local.network.vpc_id
}

resource "aws_acm_certificate" "runtime" {
  domain_name       = var.fqdn
  validation_method = "DNS"
  lifecycle { create_before_destroy = true }
}
resource "aws_route53_record" "validation" {
  zone_id = var.hosted_zone_id
  name    = tolist(aws_acm_certificate.runtime.domain_validation_options)[0].resource_record_name
  type    = tolist(aws_acm_certificate.runtime.domain_validation_options)[0].resource_record_type
  ttl     = 60
  records = [tolist(aws_acm_certificate.runtime.domain_validation_options)[0].resource_record_value]
}
resource "aws_acm_certificate_validation" "runtime" {
  certificate_arn         = aws_acm_certificate.runtime.arn
  validation_record_fqdns = [aws_route53_record.validation.fqdn]
}
resource "aws_route53_record" "runtime" {
  zone_id = var.hosted_zone_id
  name    = var.fqdn
  type    = "A"
  alias {
    name                   = data.aws_lb.foundation.dns_name
    zone_id                = data.aws_lb.foundation.zone_id
    evaluate_target_health = true
  }
}
resource "aws_lb_target_group" "identity" {
  name        = "${local.name}-identity"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = local.network.vpc_id
  health_check {
    path    = "/auth/realms/redsim"
    matcher = "200"
  }
}
resource "aws_lb_listener" "https" {
  load_balancer_arn = local.network.alb_arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.runtime.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = local.network.target_group_arns.web
  }
}
resource "aws_lb_listener_rule" "api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = local.network.target_group_arns.api
  }
  condition {
    path_pattern { values = ["/v1/*", "/health", "/ws/*"] }
  }
}
resource "aws_lb_listener_rule" "identity" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 20
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.identity.arn
  }
  condition {
    path_pattern { values = ["/auth/*"] }
  }
}

# Internal API/web OIDC requests resolve the same TLS hostname privately.
# Keep these on the internal Keycloak endpoint, avoiding an ALB hairpin.
resource "aws_service_discovery_private_dns_namespace" "runtime" {
  name = "${local.name}.internal"
  vpc  = local.network.vpc_id
}
resource "aws_service_discovery_service" "identity" {
  name = "identity"
  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.runtime.id
    dns_records {
      ttl  = 10
      type = "A"
    }
    routing_policy = "MULTIVALUE"
  }
  health_check_custom_config { failure_threshold = 1 }
}

# The web tier's server-side calls to FastAPI resolve here.
#
# The public hostname is not an option for that traffic: the web task sits in
# private subnets whose route tables carry no default route and no NAT gateway,
# the ALB is internet-facing, and no private hosted zone resolves the hostname,
# so a public value would leave every server prefetch unreachable. Same shape
# as the identity entry above, for the same reason: no ALB hairpin.
resource "aws_service_discovery_service" "api" {
  name = "api"
  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.runtime.id
    dns_records {
      ttl  = 10
      type = "A"
    }
    routing_policy = "MULTIVALUE"
  }
  health_check_custom_config { failure_threshold = 1 }
}
resource "aws_iam_role_policy" "identity_image" {
  name = "${local.name}-identity-image"
  role = "${local.name}-identity-execution"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "ecr:GetAuthorizationToken", Resource = "*" },
      { Effect = "Allow", Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"], Resource = "arn:aws:ecr:us-east-1:${var.account_id}:repository/ndia-red-team/identity" }
    ]
  })
}
