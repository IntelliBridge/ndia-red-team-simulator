# Project artifact prefixes for the demo runtime.
#
# The foundation grants the artifact-using task roles the ``assets`` prefix
# only (deploy/terraform/iam.tf, ``artifact_prefixes_by_service``). Campaign
# evidence, uploads and derived models are stored under keys that start with
# the project id (``{project_id}/models/...`` from
# ``redsim.services.ml_models`` and ``{project_id}/{run_id}/...`` from
# ``DatabaseArtifactSink``), so a project can run campaigns only after its
# prefix is granted. This root grants the operator-approved project prefixes
# to the api, scans, default and assets application roles with the same two
# statements the foundation uses. The list is an explicit input: nothing is
# derived from the database, and an empty list grants nothing.
variable "project_artifact_prefixes" {
  description = "Owner-approved project ids whose S3 artifact prefix the api, scans, default and assets task roles may read and write."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([for prefix in var.project_artifact_prefixes :
      can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", prefix)) && prefix != "assets"
    ])
    error_message = "Project ids are single path segments without slashes or wildcards, and never the reserved assets prefix."
  }
}

locals {
  project_artifact_services = length(var.project_artifact_prefixes) > 0 ? toset(["api", "scans", "default", "assets"]) : toset([])
  artifacts_bucket_arn      = "arn:aws:s3:::${local.foundation.storage_contract.artifacts.name}"
}

resource "aws_iam_role_policy" "project_artifacts" {
  for_each = local.project_artifact_services

  name = "${local.name}-${each.key}-project-artifacts"
  role = element(split("/", local.foundation.ecs_application_role_arns[each.key]), -1)

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadWriteApprovedProjectPrefixes"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = [for prefix in var.project_artifact_prefixes : "${local.artifacts_bucket_arn}/${prefix}/*"]
      },
      {
        Sid      = "ListApprovedProjectPrefixes"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = local.artifacts_bucket_arn
        Condition = {
          StringLike = {
            "s3:prefix" = [for prefix in var.project_artifact_prefixes : "${prefix}/*"]
          }
        }
      }
    ]
  })
}
