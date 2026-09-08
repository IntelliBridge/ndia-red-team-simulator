resource "aws_ecs_cluster" "foundation" {
  name = local.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  lifecycle {
    precondition {
      condition     = data.aws_vpc.selected.enable_dns_support && data.aws_vpc.selected.enable_dns_hostnames
      error_message = "The selected VPC must support DNS hostnames and resolution for private endpoints."
    }
    precondition {
      condition     = alltrue([for subnet in merge(data.aws_subnet.public, data.aws_subnet.private) : subnet.vpc_id == var.network.vpc_id])
      error_message = "All selected subnets must belong to the selected VPC."
    }
    precondition {
      condition = (
        length(toset([for subnet in data.aws_subnet.public : subnet.availability_zone])) >= 2 &&
        length(toset([for subnet in data.aws_subnet.private : subnet.availability_zone])) >= 2 &&
        length(toset([for subnet in data.aws_subnet.public : subnet.availability_zone])) == length(var.network.public_subnet_ids) &&
        length(toset([for subnet in data.aws_subnet.private : subnet.availability_zone])) == length(var.network.private_subnet_ids)
      )
      error_message = "Both tiers must span at least two AZs with exactly one selected subnet per AZ for ALB/interface endpoint compatibility."
    }
    precondition {
      condition     = alltrue([for subnet in data.aws_subnet.private : !subnet.map_public_ip_on_launch])
      error_message = "Private subnets must not auto-assign public addresses."
    }
    precondition {
      condition = alltrue(flatten([for table in data.aws_route_table.private : [
        for route in table.routes : !startswith(coalesce(try(route.gateway_id, null), "none"), "igw-")
      ]]))
      error_message = "Private subnet route tables must not route directly through an Internet gateway."
    }
  }
}

resource "aws_cloudwatch_log_group" "service" {
  for_each          = local.service_names
  name              = "/redsim/${var.environment}/${each.value}"
  retention_in_days = 30

  lifecycle {
    prevent_destroy = true
  }
}