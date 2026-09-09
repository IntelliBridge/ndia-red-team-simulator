locals {
  identity_internal = "http://identity.${aws_service_discovery_private_dns_namespace.runtime.name}:8080/auth/realms/redsim"
  common_environment = merge({
    REDSIM_ENV                  = "prod"
    REDSIM_AUTH_MODE            = "oidc"
    REDSIM_BLOB_BACKEND         = "s3"
    REDSIM_S3_BUCKET            = local.foundation.storage_contract.artifacts.name
    REDSIM_S3_REGION            = "us-east-1"
    AWS_DEFAULT_REGION          = "us-east-1"
    REDSIM_DISABLE_LLM          = "1"
    REDSIM_WORM_EXPORT          = "0"
    REDSIM_WEB_ORIGIN           = local.origin
    REDSIM_CORS_ORIGINS         = local.origin
    REDSIM_OIDC_ISSUER          = "${local.origin}/auth/realms/redsim"
    REDSIM_OIDC_JWKS_URL        = "${local.identity_internal}/protocol/openid-connect/certs"
    REDSIM_ML_ASSETS_DIR        = "/app/assets"
    REDSIM_ML_WORK_DIR          = "/tmp/redsim-ml"
    REDSIM_ML_DATASET_CACHE     = "/tmp/redsim-cache"
    REDSIM_ML_SANDBOX_MEMORY_MB = "4096"
    }, var.asset_bundle == null ? {} : {
    REDSIM_ASSET_BUNDLE_KEY    = var.asset_bundle.key
    REDSIM_ASSET_BUNDLE_SHA256 = var.asset_bundle.sha256
  })

  service_environment = {
    api     = local.common_environment
    scans   = local.common_environment
    default = local.common_environment
    beat    = local.common_environment
    assets  = local.common_environment
    migration = {
      REDSIM_DB_HOST = local.database.host
      REDSIM_DB_NAME = "redsim"
    }
    web = {
      REDSIM_ENV         = "prod"
      NEXTAUTH_URL       = local.origin
      KEYCLOAK_CLIENT_ID = "redsim-web"
      KEYCLOAK_ISSUER    = local.identity_internal
    }
    identity = {
      KC_DB                           = "postgres"
      KC_DB_URL                       = "jdbc:postgresql://${local.database.host}:5432/redsim_identity?sslmode=require"
      KC_DB_USERNAME                  = "redsim_identity"
      KC_HTTP_ENABLED                 = "true"
      KC_HTTP_RELATIVE_PATH           = "/auth"
      KC_HOSTNAME                     = "${local.origin}/auth"
      KC_HOSTNAME_BACKCHANNEL_DYNAMIC = "true"
      KC_PROXY_HEADERS                = "xforwarded"
      KC_BOOTSTRAP_ADMIN_USERNAME     = "redsim-admin"
      REDSIM_PUBLIC_ORIGIN            = local.origin
      KC_CACHE                        = "local"
    }
  }
  task_specs = {
    api = { image = "api", cpu = 512, memory = 1024, port = 8000,
    command = ["uvicorn", "redsim.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"] }
    web = { image = "web", cpu = 512, memory = 1024, port = 3000, command = null }
    scans = { image = "worker", cpu = 2048, memory = 8192, port = 0,
    command = ["celery", "-A", "redsim.workers.celery_app", "worker", "-Q", "scans", "--concurrency=1", "--loglevel=info"] }
    default = { image = "worker", cpu = 512, memory = 2048, port = 0,
    command = ["celery", "-A", "redsim.workers.celery_app", "worker", "-Q", "default", "--concurrency=1", "--loglevel=info"] }
    beat = { image = "worker", cpu = 256, memory = 512, port = 0,
    command = ["celery", "-A", "redsim.workers.celery_app", "beat", "--schedule=/tmp/celerybeat-schedule", "--loglevel=info"] }
    migration = { image = "api", cpu = 512, memory = 1024, port = 0,
    command = ["python", "-c", file("${path.module}/scripts/migrate.py")] }
    # The one-off assets task: the load-assets init container below extracts the
    # pinned bundle into the shared volume, then the main container validates
    # the mounted tree the way a worker would (manifest digests, the ml extra,
    # a sandbox child launch) and exits. Operators run seed_project.py and
    # "redsim ml seed" through this task definition with a command override
    # (scripts/run_task.py --command), so the seed sees the same read-only tree.
    assets = { image = "worker", cpu = 2048, memory = 8192, port = 0,
    command = ["redsim", "doctor", "--worker-mode"] }
    identity = { image = "identity", cpu = 512, memory = 2048, port = 8080,
    command = ["start", "--import-realm"] }
  }
  service_names = toset(["api", "web", "scans", "default", "beat", "identity"])
  # Tasks that receive the extracted asset bundle at /app/assets (read-only).
  bundle_consumers = ["api", "scans", "default", "assets"]
  target_groups    = merge(local.network.target_group_arns, { identity = aws_lb_target_group.identity.arn })
}

resource "aws_ecs_task_definition" "runtime" {
  for_each                 = local.task_specs
  family                   = "${local.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = local.foundation.ecs_execution_role_arns[each.key]
  task_role_arn            = local.foundation.ecs_application_role_arns[each.key]
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  ephemeral_storage { size_in_gib = 40 }
  container_definitions = jsonencode(concat([merge({
    name            = each.key
    image           = var.images[each.value.image]
    essential       = true
    environment     = [for name, value in local.service_environment[each.key] : { name = name, value = value }]
    secrets         = [for name, ref in lookup(var.service_secrets, each.key, {}) : { name = name, valueFrom = ref }]
    portMappings    = each.value.port == 0 ? [] : [{ containerPort = each.value.port, protocol = "tcp" }]
    mountPoints     = contains(local.bundle_consumers, each.key) && var.asset_bundle != null ? [{ sourceVolume = "assets", containerPath = "/app/assets", readOnly = true }] : []
    dependsOn       = contains(local.bundle_consumers, each.key) && var.asset_bundle != null ? [{ containerName = "load-assets", condition = "SUCCESS" }] : []
    stopTimeout     = 120
    linuxParameters = { initProcessEnabled = true }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = local.network.log_groups[each.key]
        awslogs-region        = "us-east-1"
        awslogs-stream-prefix = "ecs"
      }
    }
    }, each.value.command == null ? {} : { command = each.value.command })],
    contains(local.bundle_consumers, each.key) && var.asset_bundle != null ? [{
      name        = "load-assets"
      image       = var.images[each.value.image]
      essential   = false
      command     = ["python", "-c", file("${path.module}/scripts/load_assets.py")]
      environment = [for name, value in local.common_environment : { name = name, value = value }]
      mountPoints = [{ sourceVolume = "assets", containerPath = "/app/assets", readOnly = false }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = local.network.log_groups[each.key]
          awslogs-region        = "us-east-1"
          awslogs-stream-prefix = "assets"
        }
      }
    }] : []
  ))
  volume { name = "assets" }
  lifecycle {
    precondition {
      condition     = !var.enable_workers || var.asset_bundle != null
      error_message = "Upload and pin a real asset bundle before enabling ML workers."
    }
  }
  depends_on = [aws_iam_role_policy.identity_image]
}

resource "aws_ecs_service" "runtime" {
  for_each                           = local.service_names
  name                               = "${local.name}-${each.key}"
  cluster                            = local.network.cluster_arn
  task_definition                    = aws_ecs_task_definition.runtime[each.key].arn
  desired_count                      = var.enable_services && (contains(["scans", "default", "beat"], each.key) ? var.enable_workers : true) ? 1 : 0
  launch_type                        = "FARGATE"
  platform_version                   = "1.4.0"
  deployment_minimum_healthy_percent = each.key == "beat" || each.key == "identity" ? 0 : 100
  deployment_maximum_percent         = each.key == "beat" || each.key == "identity" ? 100 : 200
  health_check_grace_period_seconds  = each.key == "identity" ? 600 : (contains(keys(local.target_groups), each.key) ? 180 : null)
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  network_configuration {
    subnets          = local.network.private_subnet_ids
    security_groups  = [local.network.service_security_groups[each.key]]
    assign_public_ip = false
  }
  dynamic "load_balancer" {
    for_each = contains(keys(local.target_groups), each.key) ? [each.key] : []
    content {
      target_group_arn = local.target_groups[each.key]
      container_name   = each.key
      container_port   = local.task_specs[each.key].port
    }
  }
  dynamic "service_registries" {
    for_each = each.key == "identity" ? [1] : []
    content { registry_arn = aws_service_discovery_service.identity.arn }
  }
  depends_on = [aws_lb_listener_rule.api, aws_lb_listener_rule.identity]
}
output "runtime" {
  value = {
    url                     = local.origin
    cluster_arn             = local.network.cluster_arn
    service_names           = { for name, service in aws_ecs_service.runtime : name => service.name }
    task_definitions        = { for name, task in aws_ecs_task_definition.runtime : name => task.arn }
    private_subnet_ids      = local.network.private_subnet_ids
    service_security_groups = local.network.service_security_groups
  }
}
