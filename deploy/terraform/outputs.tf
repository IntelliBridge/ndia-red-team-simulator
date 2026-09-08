output "foundation_network" {
  description = "Future runtime wiring only. An ALB DNS name is not a live or authenticated application."
  value = {
    vpc_id                  = var.network.vpc_id
    private_subnet_ids      = var.network.private_subnet_ids
    service_security_groups = { for name, sg in aws_security_group.service : name => sg.id }
    database_security_group = aws_security_group.database.id
    redis_security_group    = aws_security_group.redis.id
    alb_arn                 = aws_lb.foundation.arn
    alb_dns_name            = aws_lb.foundation.dns_name
    target_group_arns       = { for name, group in aws_lb_target_group.application : name => group.arn }
    cluster_arn             = aws_ecs_cluster.foundation.arn
    log_groups              = { for name, group in aws_cloudwatch_log_group.service : name => group.name }
    interface_endpoint_ids  = { for name, endpoint in aws_vpc_endpoint.interface : name => endpoint.id }
    s3_gateway_endpoint_id  = aws_vpc_endpoint.s3.id
  }
}

output "existing_resource_references" {
  description = "Deterministic references, NOT evidence these resources exist. No OIDC/ECR/CI-role resources are managed here."
  value = {
    ecr_repository_arns = local.ecr_repository_arns
    ecr_repository_urls = local.ecr_repository_urls
    deployment_role     = "arn:aws:iam::${var.account_id}:role/${var.existing_deploy_role_name}"
  }
}

output "activation_status" {
  description = "This code-only foundation cannot activate the runtime."
  value = {
    application_services_created = false
    listener_created             = false
    migrations_executed          = false
    assets_seeded                = false
    audit_export_enabled         = false
    state_backend_provisioned    = false
    deployment_enabled           = false
  }
}