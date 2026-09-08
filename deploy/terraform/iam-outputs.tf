output "ecs_execution_role_arns" {
  description = "Execution role ARN keyed by ECS service name."
  value       = { for service, role in aws_iam_role.execution : service => role.arn }
}

output "ecs_application_role_arns" {
  description = "Application task role ARN keyed by ECS service name."
  value       = { for service, role in aws_iam_role.application : service => role.arn }
}

output "execution_role_secret_wiring" {
  description = "Secret and optional KMS key ARN wiring by execution role. Migration alone additionally receives the RDS-managed master secret for schema migrations."
  value = {
    for service in local.service_names : service => {
      role_arn      = aws_iam_role.execution[service].arn
      secret_arns   = local.execution_secret_arns[service]
      kms_key_arns  = sort(tolist(lookup(var.runtime_secret_kms_key_arns, service, toset([]))))
      master_secret = service == "migration"
    }
  }
}