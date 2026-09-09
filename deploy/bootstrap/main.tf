terraform {
  required_version = "= 1.16.1"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.63.0"
    }
  }
}

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = { Application = "redsim", Environment = var.environment, ManagedBy = "terraform" }
  }
}

variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "A verified AWS account ID is required."
  }
}
variable "environment" {
  type    = string
  default = "demo"
}
variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

locals {
  name = "ndia-red-team-${var.environment}"
  azs  = { a = "us-east-1a", b = "us-east-1b" }
}

# This small bootstrap root initially uses local state. Copy its state into
# the protected backend after creation, then use backend.tf.example.
resource "aws_s3_bucket" "state" {
  bucket        = "${local.name}-${var.account_id}-tfstate"
  force_destroy = false
  lifecycle { prevent_destroy = true }
}
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "RequireTLS", Effect = "Deny", Principal = "*", Action = "s3:*"
      Resource  = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_vpc" "runtime" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
  lifecycle { prevent_destroy = true }
}
resource "aws_internet_gateway" "runtime" {
  vpc_id = aws_vpc.runtime.id
  tags   = { Name = local.name }
}
resource "aws_subnet" "public" {
  for_each                = local.azs
  vpc_id                  = aws_vpc.runtime.id
  availability_zone       = each.value
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, each.key == "a" ? 1 : 2)
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.name}-public-${each.key}" }
}
resource "aws_subnet" "private" {
  for_each                = local.azs
  vpc_id                  = aws_vpc.runtime.id
  availability_zone       = each.value
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, each.key == "a" ? 11 : 12)
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.name}-private-${each.key}" }
}
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.runtime.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.runtime.id
  }
  tags = { Name = "${local.name}-public" }
}
resource "aws_route_table" "private" {
  for_each = local.azs
  vpc_id   = aws_vpc.runtime.id
  tags     = { Name = "${local.name}-private-${each.key}" }
}
resource "aws_route_table_association" "public" {
  for_each       = local.azs
  subnet_id      = aws_subnet.public[each.key].id
  route_table_id = aws_route_table.public.id
}
resource "aws_route_table_association" "private" {
  for_each       = local.azs
  subnet_id      = aws_subnet.private[each.key].id
  route_table_id = aws_route_table.private[each.key].id
}
output "state_bucket" { value = aws_s3_bucket.state.id }
output "network" {
  value = {
    vpc_id             = aws_vpc.runtime.id
    public_subnet_ids  = [for subnet in aws_subnet.public : subnet.id]
    private_subnet_ids = [for subnet in aws_subnet.private : subnet.id]
  }
}
