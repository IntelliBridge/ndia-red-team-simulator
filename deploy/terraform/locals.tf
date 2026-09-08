locals {
  name                  = "ndia-red-team-${var.environment}"
  partition             = "aws"
  artifacts_bucket_name = "${local.name}-${var.account_id}-${var.region}-artifacts"
  audit_bucket_name     = "${local.name}-${var.account_id}-${var.region}-audit"
  artifacts_bucket_arn  = "arn:aws:s3:::${local.artifacts_bucket_name}"
  audit_bucket_arn      = "arn:aws:s3:::${local.audit_bucket_name}"
  service_names         = toset(["api", "web", "scans", "default", "beat", "migration", "assets", "identity"])
  database_clients      = toset(["api", "scans", "default", "beat", "migration", "assets", "identity"])
  redis_clients         = toset(["api", "scans", "default", "beat"])
  artifacts_clients     = toset(["api", "scans", "default", "assets"])
  ecr_repository_arns   = { for key, name in var.existing_ecr_repository_names : key => "arn:aws:ecr:${var.region}:${var.account_id}:repository/${name}" }
  ecr_repository_urls   = { for key, name in var.existing_ecr_repository_names : key => "${var.account_id}.dkr.ecr.${var.region}.amazonaws.com/${name}" }
  service_image_families = {
    api  = "api", web = "web", scans = "worker", default = "worker",
    beat = "worker", migration = "api", assets = "worker"
  }
  tags = {
    Application = "redsim"
    Environment = var.environment
    ManagedBy   = "terraform"
    Scope       = "p7-foundation"
  }
}