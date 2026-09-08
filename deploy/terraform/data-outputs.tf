output "data_connections" {
  description = "Endpoint metadata for private data services. This contains no passwords, authentication tokens, or connection URLs."
  value = {
    database = {
      host                      = aws_db_instance.foundation.address
      port                      = aws_db_instance.foundation.port
      managed_master_secret_arn = aws_db_instance.foundation.master_user_secret[0].secret_arn
    }
    redis = {
      primary_endpoint = aws_elasticache_replication_group.foundation.primary_endpoint_address
      reader_endpoint  = aws_elasticache_replication_group.foundation.reader_endpoint_address
      port             = aws_elasticache_replication_group.foundation.port
    }
  }
}

output "storage_contract" {
  description = "Stable bucket names and ARNs for service IAM contracts."
  value = {
    artifacts = {
      name = aws_s3_bucket.artifacts.bucket
      arn  = aws_s3_bucket.artifacts.arn
    }
    audit = {
      name = aws_s3_bucket.audit.bucket
      arn  = aws_s3_bucket.audit.arn
    }
  }
}