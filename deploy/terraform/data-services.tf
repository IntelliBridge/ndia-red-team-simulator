resource "aws_db_subnet_group" "foundation" {
  name        = "${local.name}-database"
  description = "Private subnets for the ${local.name} PostgreSQL database"
  subnet_ids  = var.network.private_subnet_ids
}

resource "aws_db_parameter_group" "foundation" {
  name        = "${local.name}-postgres16"
  description = "PostgreSQL 16 parameters for ${local.name}, including pgaudit"
  family      = "postgres16"

  parameter {
    name         = "shared_preload_libraries"
    value        = "pgaudit"
    apply_method = "pending-reboot"
  }

  parameter {
    name  = "pgaudit.log"
    value = "ddl,role,write"
  }
}

resource "aws_db_instance" "foundation" {
  identifier = "${local.name}-postgres"

  engine         = "postgres"
  engine_version = "16"
  instance_class = var.database_instance_class

  db_name                     = var.database_name
  username                    = var.database_master_username
  manage_master_user_password = true
  port                        = 5432

  allocated_storage     = var.database_allocated_storage_gib
  max_allocated_storage = var.database_max_allocated_storage_gib
  storage_type          = "gp3"
  storage_encrypted     = true

  db_subnet_group_name   = aws_db_subnet_group.foundation.name
  parameter_group_name   = aws_db_parameter_group.foundation.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false
  multi_az               = var.database_multi_az

  auto_minor_version_upgrade      = true
  backup_retention_period         = 35
  copy_tags_to_snapshot           = true
  deletion_protection             = true
  delete_automated_backups        = false
  enabled_cloudwatch_logs_exports = ["postgresql"]
  final_snapshot_identifier       = "${local.name}-postgres-final"
  skip_final_snapshot             = false

  # The baseline db.t4g.small does not support Performance Insights.
  # Enabling optional monitoring requires a reviewed sizing/cost change.
  performance_insights_enabled = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_elasticache_subnet_group" "foundation" {
  name        = "${local.name}-redis"
  description = "Private subnets for the ${local.name} Redis replication group"
  subnet_ids  = var.network.private_subnet_ids
}

resource "aws_elasticache_parameter_group" "foundation" {
  name        = "${local.name}-redis7"
  description = "Non-cluster-mode Redis 7 parameters for ${local.name}"
  family      = "redis7"

  parameter {
    name  = "databases"
    value = "2"
  }
}

resource "aws_elasticache_replication_group" "foundation" {
  replication_group_id = "${local.name}-redis"
  description          = "Encrypted non-cluster-mode Redis for ${local.name}"

  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.redis_node_type
  num_cache_clusters   = var.redis_num_cache_clusters
  parameter_group_name = aws_elasticache_parameter_group.foundation.name
  port                 = 6379

  subnet_group_name  = aws_elasticache_subnet_group.foundation.name
  security_group_ids = [aws_security_group.redis.id]
  user_group_ids     = [var.redis_user_group_id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  transit_encryption_mode    = "required"

  automatic_failover_enabled = true
  auto_minor_version_upgrade = true
  multi_az_enabled           = true
  snapshot_retention_limit   = 7

  lifecycle {
    prevent_destroy = true
  }
}