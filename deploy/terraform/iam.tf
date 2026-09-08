locals {
  ecs_task_assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "EcsTasksOnly"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = var.account_id
        }
        ArnLike = {
          "aws:SourceArn" = "arn:${local.partition}:ecs:${var.region}:${var.account_id}:*"
        }
      }
    }]
  })

  execution_secret_arns = {
    for service in local.service_names : service => sort(tolist(setunion(
      lookup(var.runtime_secret_arns, service, toset([])),
      service == "migration" ? toset([aws_db_instance.foundation.master_user_secret[0].secret_arn]) : toset([])
    )))
  }

}

resource "aws_iam_role" "execution" {
  for_each = local.service_names

  name               = "ndia-red-team-${var.environment}-${each.key}-execution"
  assume_role_policy = local.ecs_task_assume_role_policy

  tags = {
    Service = each.key
    Role    = "ecs-execution"
  }
}

resource "aws_iam_role" "application" {
  for_each = local.service_names

  name               = "ndia-red-team-${var.environment}-${each.key}-application"
  assume_role_policy = local.ecs_task_assume_role_policy

  tags = {
    Service = each.key
    Role    = "ecs-application"
  }
}

resource "aws_iam_role_policy" "execution" {
  for_each = local.service_names

  name = "ndia-red-team-${var.environment}-${each.key}-execution"
  role = aws_iam_role.execution[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      each.key == "identity" ? [] : [
        {
          Sid      = "EcrAuthorization"
          Effect   = "Allow"
          Action   = ["ecr:GetAuthorizationToken"]
          Resource = "*"
        },
        {
          Sid    = "PullServiceImage"
          Effect = "Allow"
          Action = [
            "ecr:BatchCheckLayerAvailability",
            "ecr:BatchGetImage",
            "ecr:GetDownloadUrlForLayer",
          ]
          Resource = local.ecr_repository_arns[local.service_image_families[each.key]]
        }
      ],
      [
        {
          Sid    = "WriteOwnLogs"
          Effect = "Allow"
          Action = [
            "logs:CreateLogStream",
            "logs:PutLogEvents",
          ]
          Resource = "${aws_cloudwatch_log_group.service[each.key].arn}:*"
        }
      ],
      length(local.execution_secret_arns[each.key]) == 0 ? [] : [
        {
          Sid      = "ReadConfiguredRuntimeSecrets"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = local.execution_secret_arns[each.key]
        }
      ],
      length(lookup(var.runtime_secret_kms_key_arns, each.key, toset([]))) == 0 ? [] : [
        {
          Sid      = "DecryptConfiguredRuntimeSecrets"
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = sort(tolist(var.runtime_secret_kms_key_arns[each.key]))
          Condition = {
            StringEquals = {
              "kms:CallerAccount" = var.account_id
              "kms:ViaService"    = "secretsmanager.${var.region}.amazonaws.com"
            }
          }
        }
      ]
    )
  })
}

resource "aws_iam_role_policy" "application_artifacts" {
  for_each = var.artifact_prefixes_by_service

  name = "ndia-red-team-${var.environment}-${each.key}-artifacts"
  role = aws_iam_role.application[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadWriteApprovedArtifactPrefixes"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = [for prefix in each.value : "${local.artifacts_bucket_arn}/${prefix}/*"]
      },
      {
        Sid      = "ListApprovedArtifactPrefixes"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = local.artifacts_bucket_arn
        Condition = {
          StringLike = {
            # A bare prefix also lists sibling names such as approved-other.
            "s3:prefix" = [for prefix in each.value : "${prefix}/*"]
          }
        }
      }
    ]
  })
}