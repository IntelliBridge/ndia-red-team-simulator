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
      address = "database.dev.internal"
      master_user_secret = [{
        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-foundation"
      }]
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
}

run "foundation_baseline" {
  command = plan

  assert {
    condition     = aws_ecs_cluster.foundation.name == "ndia-red-team-dev"
    error_message = "The ECS cluster must use the environment-scoped foundation name."
  }

  assert {
    condition     = anytrue([for setting in aws_ecs_cluster.foundation.setting : setting.name == "containerInsights" && setting.value == "enabled"])
    error_message = "Container Insights must be enabled."
  }

  assert {
    condition     = aws_lb.foundation.internal == false && aws_lb.foundation.load_balancer_type == "application"
    error_message = "The reserved load balancer must remain an internet-facing ALB."
  }

  assert {
    condition     = aws_lb.foundation.enable_deletion_protection && aws_lb.foundation.drop_invalid_header_fields
    error_message = "The ALB must retain deletion protection and invalid-header filtering."
  }

  assert {
    condition     = toset(aws_lb.foundation.subnets) == toset(var.network.public_subnet_ids)
    error_message = "The ALB must use only the explicitly selected public subnets."
  }

  assert {
    condition     = aws_lb_target_group.application["api"].target_type == "ip" && aws_lb_target_group.application["api"].port == 8000
    error_message = "The API target group must support Fargate IP targets on port 8000."
  }

  assert {
    condition     = aws_lb_target_group.application["web"].target_type == "ip" && aws_lb_target_group.application["web"].port == 3000
    error_message = "The web target group must support Fargate IP targets on port 3000."
  }

  assert {
    condition     = length(aws_vpc_endpoint.interface) == 4 && alltrue([for endpoint in aws_vpc_endpoint.interface : endpoint.vpc_endpoint_type == "Interface" && endpoint.private_dns_enabled])
    error_message = "All four private interface endpoints must use private DNS."
  }

  assert {
    condition     = aws_vpc_endpoint.s3.vpc_endpoint_type == "Gateway" && toset(aws_vpc_endpoint.s3.route_table_ids) == toset(["rtb-00000000000000021", "rtb-00000000000000022"])
    error_message = "The S3 gateway endpoint must attach only to selected private route tables."
  }

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.reviewer_https) == 1 && aws_vpc_security_group_ingress_rule.reviewer_https["198.51.100.0/24"].from_port == 443
    error_message = "Reviewer ingress must be narrowly scoped to HTTPS."
  }

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.database) == 7 && length(aws_vpc_security_group_ingress_rule.redis) == 4
    error_message = "Database and Redis ingress must be limited to the expected service sets."
  }

  assert {
    condition     = alltrue([for group in aws_cloudwatch_log_group.service : group.retention_in_days == 30])
    error_message = "Every service log group must retain logs for 30 days."
  }

  assert {
    condition     = length(aws_iam_role_policy.application_artifacts) == 0
    error_message = "The default foundation must grant no unapproved business S3 prefixes."
  }
}

run "storage_and_data_services" {
  command = plan

  assert {
    condition     = aws_s3_bucket.artifacts.force_destroy == false && aws_s3_bucket.audit.force_destroy == false
    error_message = "Neither durable bucket may allow force destruction."
  }

  assert {
    condition     = aws_s3_bucket.audit.object_lock_enabled
    error_message = "The audit bucket must have Object Lock enabled."
  }

  assert {
    condition     = aws_s3_bucket_versioning.artifacts.versioning_configuration[0].status == "Enabled" && aws_s3_bucket_versioning.audit.versioning_configuration[0].status == "Enabled"
    error_message = "Both durable buckets must be versioned."
  }

  assert {
    condition = (
      alltrue(flatten([for rule in aws_s3_bucket_server_side_encryption_configuration.artifacts.rule : [
        for encryption in rule.apply_server_side_encryption_by_default : encryption.sse_algorithm == "AES256"
      ]])) &&
      alltrue(flatten([for rule in aws_s3_bucket_server_side_encryption_configuration.audit.rule : [
        for encryption in rule.apply_server_side_encryption_by_default : encryption.sse_algorithm == "AES256"
      ]]))
    )
    error_message = "Both durable buckets must enable server-side encryption."
  }

  assert {
    condition     = aws_s3_bucket_object_lock_configuration.audit.object_lock_enabled == "Enabled" && length(aws_s3_bucket_object_lock_configuration.audit.rule) == 0
    error_message = "Audit Object Lock must be enabled without an irreversible default retention rule."
  }

  assert {
    condition     = alltrue([for block in [aws_s3_bucket_public_access_block.artifacts, aws_s3_bucket_public_access_block.audit] : block.block_public_acls && block.block_public_policy && block.ignore_public_acls && block.restrict_public_buckets])
    error_message = "Public access must be fully blocked on both buckets."
  }

  assert {
    condition     = aws_db_instance.foundation.manage_master_user_password && aws_db_instance.foundation.storage_encrypted && aws_db_instance.foundation.publicly_accessible == false
    error_message = "RDS must use an AWS-managed master secret, encrypted storage, and private networking."
  }

  assert {
    condition     = aws_db_instance.foundation.engine == "postgres" && startswith(aws_db_instance.foundation.engine_version, "16") && aws_db_instance.foundation.storage_type == "gp3"
    error_message = "RDS must remain PostgreSQL 16 on gp3 storage."
  }

  assert {
    condition     = aws_db_instance.foundation.backup_retention_period == 35 && aws_db_instance.foundation.deletion_protection && aws_db_instance.foundation.skip_final_snapshot == false
    error_message = "RDS durability controls must remain enabled."
  }

  assert {
    condition     = aws_db_instance.foundation.performance_insights_enabled == false
    error_message = "Performance Insights must remain disabled for the baseline db.t4g.small instance class."
  }

  assert {
    condition     = aws_db_instance.foundation.master_user_secret[0].secret_arn == "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-foundation"
    error_message = "The mocked RDS managed-secret metadata must remain available to migration wiring."
  }

  assert {
    condition     = aws_elasticache_replication_group.foundation.user_group_ids == toset(["redsim-dev-users"])
    error_message = "Redis must use the externally managed user group."
  }

  assert {
    condition     = aws_elasticache_replication_group.foundation.at_rest_encryption_enabled && aws_elasticache_replication_group.foundation.transit_encryption_enabled && aws_elasticache_replication_group.foundation.transit_encryption_mode == "required"
    error_message = "Redis encryption at rest and required TLS in transit must remain enabled."
  }

  assert {
    condition     = aws_elasticache_replication_group.foundation.automatic_failover_enabled && aws_elasticache_replication_group.foundation.multi_az_enabled && aws_elasticache_replication_group.foundation.num_cache_clusters >= 2
    error_message = "Redis must remain multi-node, Multi-AZ, and failover-enabled."
  }

  assert {
    condition     = aws_elasticache_replication_group.foundation.snapshot_retention_limit == 7
    error_message = "Redis snapshots must retain seven days."
  }
}