mock_provider "aws" {
  override_data {
    target          = data.aws_vpc.selected
    override_during = plan
    values = {
      enable_dns_support   = true
      enable_dns_hostnames = true
    }
  }

  override_data {
    target          = data.aws_subnet.public["subnet-00000000000000011"]
    override_during = plan
    values = {
      vpc_id                  = "vpc-00000000000000001"
      availability_zone       = "us-east-1a"
      map_public_ip_on_launch = true
    }
  }

  override_data {
    target          = data.aws_subnet.public["subnet-00000000000000012"]
    override_during = plan
    values = {
      vpc_id                  = "vpc-00000000000000001"
      availability_zone       = "us-east-1b"
      map_public_ip_on_launch = true
    }
  }

  override_data {
    target          = data.aws_subnet.private["subnet-00000000000000021"]
    override_during = plan
    values = {
      vpc_id                  = "vpc-00000000000000001"
      availability_zone       = "us-east-1a"
      map_public_ip_on_launch = false
    }
  }

  override_data {
    target          = data.aws_subnet.private["subnet-00000000000000022"]
    override_during = plan
    values = {
      vpc_id                  = "vpc-00000000000000001"
      availability_zone       = "us-east-1b"
      map_public_ip_on_launch = false
    }
  }

  override_data {
    target          = data.aws_route_table.private["subnet-00000000000000021"]
    override_during = plan
    values = {
      id     = "rtb-00000000000000021"
      routes = []
    }
  }

  override_data {
    target          = data.aws_route_table.private["subnet-00000000000000022"]
    override_during = plan
    values = {
      id     = "rtb-00000000000000022"
      routes = []
    }
  }

  override_resource {
    target          = aws_db_instance.foundation
    override_during = plan
    values = {
      master_user_secret = [{
        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-foundation"
      }]
    }
  }

  override_resource {
    target          = aws_cloudwatch_log_group.service
    override_during = plan
    values = {
      arn = "arn:aws:logs:us-east-1:123456789012:log-group:mock-service"
    }
  }
}

variables {
  account_id  = "123456789012"
  environment = "dev"
  network = {
    vpc_id = "vpc-00000000000000001"
    public_subnet_ids = [
      "subnet-00000000000000011",
      "subnet-00000000000000012",
    ]
    private_subnet_ids = [
      "subnet-00000000000000021",
      "subnet-00000000000000022",
    ]
  }
  reviewer_ipv4_cidrs = ["198.51.100.0/24"]
  redis_user_group_id = "redsim-dev-users"
  artifact_prefixes_by_service = {
    api     = ["approved/api"]
    scans   = ["approved/scans"]
    default = ["approved/default"]
    assets  = ["approved/assets"]
  }
  runtime_secret_arns = {
    api       = ["arn:aws:secretsmanager:us-east-1:123456789012:secret:dev/api"]
    migration = ["arn:aws:secretsmanager:us-east-1:123456789012:secret:dev/migration"]
  }
  runtime_secret_kms_key_arns = {
    api = ["arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001"]
  }
}

run "role_boundaries_and_secret_scopes" {
  command = plan

  assert {
    condition     = length(aws_iam_role.execution) == 8 && length(aws_iam_role.application) == 8
    error_message = "Each service must have distinct execution and application roles."
  }

  assert {
    condition     = alltrue([for service, role in aws_iam_role.execution : role.name == "ndia-red-team-dev-${service}-execution"])
    error_message = "Execution role names must be environment- and service-scoped."
  }

  assert {
    condition     = alltrue([for service, role in aws_iam_role.application : role.name == "ndia-red-team-dev-${service}-application"])
    error_message = "Application role names must be environment- and service-scoped."
  }

  assert {
    condition = alltrue([
      for role in concat(values(aws_iam_role.execution), values(aws_iam_role.application)) :
      jsondecode(role.assume_role_policy).Statement[0].Principal.Service == "ecs-tasks.amazonaws.com" &&
      jsondecode(role.assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    ])
    error_message = "Task roles must trust only ECS tasks from the configured account."
  }

  assert {
    condition     = contains([for statement in jsondecode(aws_iam_role_policy.execution["api"].policy).Statement : statement.Sid], "ReadConfiguredRuntimeSecrets")
    error_message = "The API execution role must read its configured runtime secret."
  }

  assert {
    condition = one([
      for statement in jsondecode(aws_iam_role_policy.execution["api"].policy).Statement :
      statement.Resource if statement.Sid == "ReadConfiguredRuntimeSecrets"
    ]) == ["arn:aws:secretsmanager:us-east-1:123456789012:secret:dev/api"]
    error_message = "The API execution role must receive only its own configured secret."
  }

  assert {
    condition = toset(one([
      for statement in jsondecode(aws_iam_role_policy.execution["migration"].policy).Statement :
      statement.Resource if statement.Sid == "ReadConfiguredRuntimeSecrets"
      ])) == toset([
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:dev/migration",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-foundation",
    ])
    error_message = "Migration alone must receive both its configured secret and the RDS-managed master secret."
  }

  assert {
    condition = alltrue([
      for service in setsubtract(local.service_names, toset(["api", "migration"])) :
      !contains([for statement in jsondecode(aws_iam_role_policy.execution[service].policy).Statement : statement.Sid], "ReadConfiguredRuntimeSecrets")
    ])
    error_message = "Services without configured secrets must not receive Secrets Manager access."
  }

  assert {
    condition = one([
      for statement in jsondecode(aws_iam_role_policy.execution["api"].policy).Statement :
      statement.Resource if statement.Sid == "DecryptConfiguredRuntimeSecrets"
    ]) == ["arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001"]
    error_message = "KMS decrypt must be scoped to the API's configured key."
  }

  assert {
    condition     = length(aws_iam_role_policy.application_artifacts) == 4
    error_message = "Each explicitly configured artifact client must receive one scoped policy."
  }

  assert {
    condition = alltrue([
      for service, policy in aws_iam_role_policy.application_artifacts :
      toset(one([
        for statement in jsondecode(policy.policy).Statement :
        statement.Condition.StringLike["s3:prefix"] if statement.Sid == "ListApprovedArtifactPrefixes"
        ])) == toset([
        for prefix in var.artifact_prefixes_by_service[service] : "${prefix}/*"
      ])
    ])
    error_message = "ListBucket conditions must contain only exact slash-delimited prefix patterns and never bare prefixes."
  }

  assert {
    condition = alltrue([
      for policy in values(aws_iam_role_policy.application_artifacts) :
      alltrue([
        for statement in jsondecode(policy.policy).Statement :
        !can(regex("audit", jsonencode(statement.Resource)))
      ])
    ])
    error_message = "No application role may receive audit-bucket grants."
  }

  assert {
    condition = alltrue(flatten([
      for policy in values(aws_iam_role_policy.application_artifacts) : [
        for statement in jsondecode(policy.policy).Statement :
        alltrue([for action in tolist(statement.Action) : !startswith(lower(action), "iam:")])
      ]
    ]))
    error_message = "Application policies must not grant IAM actions."
  }

  assert {
    condition     = output.execution_role_secret_wiring["migration"].master_secret && output.execution_role_secret_wiring["api"].master_secret == false
    error_message = "The secret-wiring contract must identify migration as the sole managed-master-secret consumer."
  }
}