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

run "reject_world_ingress" {
  command = plan

  variables {
    reviewer_ipv4_cidrs = ["0.0.0.0/0"]
  }

  expect_failures = [var.reviewer_ipv4_cidrs]
}

run "reject_network_overlap" {
  command = plan

  variables {
    network = {
      vpc_id = "vpc-00000000000000001"
      public_subnet_ids = [
        "subnet-00000000000000011",
        "subnet-00000000000000012",
      ]
      private_subnet_ids = [
        "subnet-00000000000000011",
        "subnet-00000000000000022",
      ]
    }
  }

  expect_failures = [var.network]
}

run "reject_private_public_ip_mapping" {
  command = plan

  override_data {
    target = data.aws_subnet.private["subnet-00000000000000021"]
    values = {
      vpc_id                  = "vpc-00000000000000001"
      availability_zone       = "us-east-1a"
      map_public_ip_on_launch = true
    }
  }

  expect_failures = [aws_ecs_cluster.foundation]
}

run "reject_subnet_from_wrong_vpc" {
  command = plan

  override_data {
    target = data.aws_subnet.private["subnet-00000000000000021"]
    values = {
      vpc_id                  = "vpc-00000000000000002"
      availability_zone       = "us-east-1a"
      map_public_ip_on_launch = false
    }
  }

  expect_failures = [aws_ecs_cluster.foundation]
}

run "reject_single_az_private_tier" {
  command = plan

  override_data {
    target = data.aws_subnet.private["subnet-00000000000000022"]
    values = {
      vpc_id                  = "vpc-00000000000000001"
      availability_zone       = "us-east-1a"
      map_public_ip_on_launch = false
    }
  }

  expect_failures = [aws_ecs_cluster.foundation]
}

run "reject_public_subnets_not_each_in_distinct_az" {
  command = plan

  variables {
    network = {
      vpc_id = "vpc-00000000000000001"
      public_subnet_ids = [
        "subnet-00000000000000011",
        "subnet-00000000000000012",
        "subnet-00000000000000013",
      ]
      private_subnet_ids = [
        "subnet-00000000000000021",
        "subnet-00000000000000022",
      ]
    }
  }

  override_data {
    target = data.aws_subnet.public["subnet-00000000000000013"]
    values = {
      vpc_id                  = "vpc-00000000000000001"
      availability_zone       = "us-east-1a"
      map_public_ip_on_launch = true
    }
  }

  expect_failures = [aws_ecs_cluster.foundation]
}

run "reject_private_subnets_not_each_in_distinct_az" {
  command = plan

  variables {
    network = {
      vpc_id = "vpc-00000000000000001"
      public_subnet_ids = [
        "subnet-00000000000000011",
        "subnet-00000000000000012",
      ]
      private_subnet_ids = [
        "subnet-00000000000000021",
        "subnet-00000000000000022",
        "subnet-00000000000000023",
      ]
    }
  }

  override_data {
    target = data.aws_subnet.private["subnet-00000000000000023"]
    values = {
      vpc_id                  = "vpc-00000000000000001"
      availability_zone       = "us-east-1a"
      map_public_ip_on_launch = false
    }
  }

  override_data {
    target = data.aws_route_table.private["subnet-00000000000000023"]
    values = {
      id     = "rtb-00000000000000023"
      routes = []
    }
  }

  expect_failures = [aws_ecs_cluster.foundation]
}

run "reject_private_igw_route" {
  command = plan

  override_data {
    target = data.aws_route_table.private["subnet-00000000000000021"]
    values = {
      id = "rtb-00000000000000021"
      routes = [{
        cidr_block = "0.0.0.0/0"
        gateway_id = "igw-00000000000000001"
      }]
    }
  }

  expect_failures = [aws_ecs_cluster.foundation]
}

run "reject_cross_account_secret" {
  command = plan

  variables {
    runtime_secret_arns = {
      api = ["arn:aws:secretsmanager:us-east-1:210987654321:secret:dev/api"]
    }
  }

  expect_failures = [var.runtime_secret_arns]
}

run "reject_invalid_secret_arn" {
  command = plan

  variables {
    runtime_secret_arns = {
      api = ["not-an-arn"]
    }
  }

  expect_failures = [var.runtime_secret_arns]
}

run "reject_wildcard_artifact_prefix" {
  command = plan

  variables {
    artifact_prefixes_by_service = {
      api = ["approved/*"]
    }
  }

  expect_failures = [var.artifact_prefixes_by_service]
}

run "reject_unapproved_artifact_service" {
  command = plan

  variables {
    artifact_prefixes_by_service = {
      web = ["approved/web"]
    }
  }

  expect_failures = [var.artifact_prefixes_by_service]
}

run "reject_insufficient_storage_autoscaling_headroom" {
  command = plan

  variables {
    database_allocated_storage_gib     = 20
    database_max_allocated_storage_gib = 21
  }

  expect_failures = [var.database_max_allocated_storage_gib]
}

run "reject_public_https_without_opt_in" {
  command = plan
  variables { reviewer_ipv4_cidrs = ["0.0.0.0/0"] }
  expect_failures = [var.reviewer_ipv4_cidrs]
}

run "allow_explicit_public_https" {
  command = plan
  variables {
    reviewer_ipv4_cidrs = ["0.0.0.0/0"]
    allow_public_https  = true
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.reviewer_https["0.0.0.0/0"].from_port == 443 && aws_vpc_security_group_ingress_rule.reviewer_https["0.0.0.0/0"].to_port == 443 && !aws_db_instance.foundation.publicly_accessible
    error_message = "Public demo access is HTTPS-only; the database must stay private."
  }
}
