mock_provider "aws" {
  mock_data "aws_lb" {
    defaults = { dns_name = "test.us-east-1.elb.amazonaws.com", zone_id = "Z123456789" }
  }
}
override_data {
  target = data.terraform_remote_state.foundation
  values = { outputs = { "foundation_network" : { "vpc_id" : "vpc-0123456789abcdef0", "private_subnet_ids" : ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"], "service_security_groups" : { "api" : "sg-0123456789abcdef0", "web" : "sg-0123456789abcdef0", "scans" : "sg-0123456789abcdef0", "default" : "sg-0123456789abcdef0", "beat" : "sg-0123456789abcdef0", "migration" : "sg-0123456789abcdef0", "assets" : "sg-0123456789abcdef0", "identity" : "sg-0123456789abcdef0" }, "alb_arn" : "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test/1234567890123456", "cluster_arn" : "arn:aws:ecs:us-east-1:123456789012:cluster/ndia-red-team-test", "target_group_arns" : { "api" : "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-api/1234567890123456", "web" : "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-web/1234567890123456" }, "log_groups" : { "api" : "/redsim/test/api", "web" : "/redsim/test/web", "scans" : "/redsim/test/scans", "default" : "/redsim/test/default", "beat" : "/redsim/test/beat", "migration" : "/redsim/test/migration", "assets" : "/redsim/test/assets", "identity" : "/redsim/test/identity" } }, "data_connections" : { "database" : { "host" : "postgres.example.test" }, "redis" : { "primary_endpoint" : "redis.example.test" } }, "storage_contract" : { "artifacts" : { "name" : "test-artifacts" } }, "ecs_execution_role_arns" : { "api" : "arn:aws:iam::123456789012:role/ndia-red-team-test-api-execution", "web" : "arn:aws:iam::123456789012:role/ndia-red-team-test-web-execution", "scans" : "arn:aws:iam::123456789012:role/ndia-red-team-test-scans-execution", "default" : "arn:aws:iam::123456789012:role/ndia-red-team-test-default-execution", "beat" : "arn:aws:iam::123456789012:role/ndia-red-team-test-beat-execution", "migration" : "arn:aws:iam::123456789012:role/ndia-red-team-test-migration-execution", "assets" : "arn:aws:iam::123456789012:role/ndia-red-team-test-assets-execution", "identity" : "arn:aws:iam::123456789012:role/ndia-red-team-test-identity-execution" }, "ecs_application_role_arns" : { "api" : "arn:aws:iam::123456789012:role/ndia-red-team-test-api-application", "web" : "arn:aws:iam::123456789012:role/ndia-red-team-test-web-application", "scans" : "arn:aws:iam::123456789012:role/ndia-red-team-test-scans-application", "default" : "arn:aws:iam::123456789012:role/ndia-red-team-test-default-application", "beat" : "arn:aws:iam::123456789012:role/ndia-red-team-test-beat-application", "migration" : "arn:aws:iam::123456789012:role/ndia-red-team-test-migration-application", "assets" : "arn:aws:iam::123456789012:role/ndia-red-team-test-assets-application", "identity" : "arn:aws:iam::123456789012:role/ndia-red-team-test-identity-application" } } }
}
variables {
  account_id      = "123456789012"
  environment     = "test"
  state_bucket    = "test-state"
  fqdn            = "redsim.example.test"
  hosted_zone_id  = "Z123456789"
  service_secrets = {}
  images          = { "api" : "123456789012.dkr.ecr.us-east-1.amazonaws.com/ndia-red-team/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "web" : "123456789012.dkr.ecr.us-east-1.amazonaws.com/ndia-red-team/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "worker" : "123456789012.dkr.ecr.us-east-1.amazonaws.com/ndia-red-team/worker@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "identity" : "123456789012.dkr.ecr.us-east-1.amazonaws.com/ndia-red-team/identity@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
}
run "stage_without_starting_services" {
  command = plan
  assert {
    condition     = alltrue([for svc in aws_ecs_service.runtime : svc.desired_count == 0])
    error_message = "Provisioning task definitions must not start workloads before migration."
  }
  assert {
    condition     = alltrue([for svc in aws_ecs_service.runtime : !svc.network_configuration[0].assign_public_ip])
    error_message = "Serving tasks must not receive public IPs."
  }
  assert {
    condition     = jsondecode(aws_ecs_task_definition.runtime["api"].container_definitions)[0].command[0] == "uvicorn"
    error_message = "Serving API tasks must not execute migrations."
  }
}
run "start_core_only" {
  command = plan
  variables { enable_services = true }
  assert {
    condition     = aws_ecs_service.runtime["api"].desired_count == 1 && aws_ecs_service.runtime["identity"].desired_count == 1 && aws_ecs_service.runtime["scans"].desired_count == 0
    error_message = "Core activation must leave unseeded workers stopped."
  }
}
run "singleton_scheduler" {
  command = plan
  variables {
    enable_services = true
    enable_workers  = true
    asset_bundle    = { key = "assets/bundles/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tar.gz", sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
  }
  assert {
    condition     = aws_ecs_service.runtime["beat"].desired_count == 1 && aws_ecs_service.runtime["beat"].deployment_maximum_percent == 100 && aws_ecs_service.runtime["beat"].deployment_minimum_healthy_percent == 0
    error_message = "Beat must not overlap with itself during a rollout."
  }
  assert {
    condition     = alltrue([for task in aws_ecs_task_definition.runtime : strcontains(jsondecode(task.container_definitions)[0].image, "@sha256:")])
    error_message = "Task images must be immutable."
  }
}
