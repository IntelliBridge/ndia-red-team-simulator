variable "database_name" {
  description = "Initial PostgreSQL database name."
  type        = string
  default     = "redsim"

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9_]{0,62}$", var.database_name))
    error_message = "The database name must start with a letter and contain at most 63 letters, digits, or underscores."
  }
}

variable "database_master_username" {
  description = "PostgreSQL master username. AWS generates and manages the password in Secrets Manager."
  type        = string
  default     = "foundation_admin"

  validation {
    condition = (
      can(regex("^[A-Za-z][A-Za-z0-9_]{0,62}$", var.database_master_username)) &&
      !contains(["postgres", "rdsadmin"], lower(var.database_master_username))
    )
    error_message = "The master username must be 1-63 letters, digits, or underscores, start with a letter, and not be a reserved RDS username."
  }
}

variable "database_instance_class" {
  description = "RDS instance class selected through the reviewed environment configuration."
  type        = string
  default     = "db.t4g.small"

  validation {
    condition     = can(regex("^db\\.[a-z0-9]+\\.[a-z0-9]+$", var.database_instance_class))
    error_message = "Provide a valid RDS instance class such as db.t4g.small."
  }
}

variable "database_allocated_storage_gib" {
  description = "Initial encrypted PostgreSQL gp3 storage in GiB."
  type        = number
  default     = 20

  validation {
    condition     = var.database_allocated_storage_gib >= 20 && var.database_allocated_storage_gib <= 65536
    error_message = "PostgreSQL allocated storage must be between 20 and 65536 GiB."
  }
}

variable "database_max_allocated_storage_gib" {
  description = "PostgreSQL storage autoscaling ceiling in GiB. RDS requires this to be at least 10% above allocated storage."
  type        = number
  default     = 100

  validation {
    condition = (
      var.database_max_allocated_storage_gib >= ceil(var.database_allocated_storage_gib * 1.1) &&
      var.database_max_allocated_storage_gib <= 65536
    )
    error_message = "The storage autoscaling ceiling must be at least 10% above allocated storage (ceil(allocated * 1.1) GiB) and no more than 65536 GiB."
  }
}

variable "database_multi_az" {
  description = "Whether the PostgreSQL instance maintains a synchronous standby in another Availability Zone."
  type        = bool
  default     = true
}

variable "redis_node_type" {
  description = "ElastiCache node type selected through the reviewed environment configuration."
  type        = string
  default     = "cache.t4g.small"

  validation {
    condition     = can(regex("^cache\\.[a-z0-9]+\\.[a-z0-9]+$", var.redis_node_type))
    error_message = "Provide a valid ElastiCache node type such as cache.t4g.small."
  }
}

variable "redis_num_cache_clusters" {
  description = "Total nodes in the non-cluster-mode Redis replication group, including its primary."
  type        = number
  default     = 2

  validation {
    condition     = var.redis_num_cache_clusters >= 2 && var.redis_num_cache_clusters <= 6 && floor(var.redis_num_cache_clusters) == var.redis_num_cache_clusters
    error_message = "Use 2-6 Redis nodes so automatic failover has at least one replica."
  }
}

variable "redis_user_group_id" {
  description = "ID of the pre-existing Redis user group managed outside this Terraform configuration. Supply identifiers only, never passwords or tokens."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,39}$", var.redis_user_group_id))
    error_message = "Provide a 1-40 character ElastiCache user group ID starting with a lowercase letter."
  }
}