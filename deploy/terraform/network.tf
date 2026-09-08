data "aws_vpc" "selected" {
  id = var.network.vpc_id
}

data "aws_subnet" "public" {
  for_each = var.network.public_subnet_ids
  id       = each.value
}

data "aws_subnet" "private" {
  for_each = var.network.private_subnet_ids
  id       = each.value
}

data "aws_route_table" "private" {
  for_each  = var.network.private_subnet_ids
  subnet_id = each.value
}

resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "Restricted future HTTPS ingress; no listener or live targets in this foundation."
  vpc_id      = var.network.vpc_id
}

resource "aws_security_group" "service" {
  for_each    = local.service_names
  name        = "${local.name}-${each.key}"
  description = "Reserved ${each.key} service boundary, no workloads created."
  vpc_id      = var.network.vpc_id
}

resource "aws_security_group" "database" {
  name        = "${local.name}-postgres"
  description = "PostgreSQL reachable only by explicitly enumerated service security groups."
  vpc_id      = var.network.vpc_id
}

resource "aws_security_group" "redis" {
  name        = "${local.name}-redis"
  description = "Redis reachable only by Celery/API service security groups."
  vpc_id      = var.network.vpc_id
}

resource "aws_security_group" "endpoints" {
  name        = "${local.name}-endpoints"
  description = "Private AWS service endpoints for future ECS workloads."
  vpc_id      = var.network.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "reviewer_https" {
  for_each          = var.reviewer_ipv4_cidrs
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Approved reviewer HTTPS range."
}

resource "aws_vpc_security_group_ingress_rule" "alb_to_service" {
  for_each                     = { api = 8000, web = 3000, identity = 8080 }
  security_group_id            = aws_security_group.service[each.key].id
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = each.value
  to_port                      = each.value
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_service" {
  for_each                     = { api = 8000, web = 3000, identity = 8080 }
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.service[each.key].id
  from_port                    = each.value
  to_port                      = each.value
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "database" {
  for_each                     = local.database_clients
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.service[each.value].id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "database" {
  for_each                     = local.database_clients
  security_group_id            = aws_security_group.service[each.value].id
  referenced_security_group_id = aws_security_group.database.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "redis" {
  for_each                     = local.redis_clients
  security_group_id            = aws_security_group.redis.id
  referenced_security_group_id = aws_security_group.service[each.value].id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "redis" {
  for_each                     = local.redis_clients
  security_group_id            = aws_security_group.service[each.value].id
  referenced_security_group_id = aws_security_group.redis.id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "endpoint_https" {
  for_each                     = local.service_names
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.service[each.value].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "endpoint_https" {
  for_each                     = local.service_names
  security_group_id            = aws_security_group.service[each.value].id
  referenced_security_group_id = aws_security_group.endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

# Every image family needs ECR's S3 layer transport, not just S3 business access.
resource "aws_vpc_security_group_egress_rule" "s3_https" {
  for_each          = local.service_names
  security_group_id = aws_security_group.service[each.value].id
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "pythia_https" {
  for_each          = var.pythia_ipv4_cidrs
  security_group_id = aws_security_group.service["default"].id
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Approved Pythia destination only; routing/TLS remain rollout prerequisites."
}

# Server-side web/API access to the retained private Keycloak runtime.
resource "aws_vpc_security_group_ingress_rule" "oidc" {
  for_each                     = toset(["api", "web"])
  security_group_id            = aws_security_group.service["identity"].id
  referenced_security_group_id = aws_security_group.service[each.value].id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "oidc" {
  for_each                     = toset(["api", "web"])
  security_group_id            = aws_security_group.service[each.value].id
  referenced_security_group_id = aws_security_group.service["identity"].id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(["ecr.api", "ecr.dkr", "logs", "secretsmanager"])
  vpc_id              = var.network.vpc_id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.network.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "*"
      Resource  = "*"
      Condition = { StringEquals = { "aws:PrincipalAccount" = var.account_id } }
    }]
  })
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.network.vpc_id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = toset([for table in data.aws_route_table.private : table.id])
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ScopedApplicationStorage"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:ListBucket", "s3:GetObject", "s3:PutObject"]
        Resource  = [local.artifacts_bucket_arn, "${local.artifacts_bucket_arn}/*"]
        Condition = { StringEquals = { "aws:PrincipalAccount" = var.account_id } }
      },
      {
        Sid       = "EcrLayerTransport"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::prod-${var.region}-starport-layer-bucket/*"
      }
    ]
  })
}