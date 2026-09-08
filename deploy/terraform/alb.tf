resource "aws_lb" "foundation" {
  name                       = "${local.name}-alb"
  internal                   = false
  load_balancer_type         = "application"
  subnets                    = var.network.public_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  enable_deletion_protection = true
  drop_invalid_header_fields = true
  enable_http2               = true

  # No listeners, certificates, target attachments, or ECS services in this slice.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_lb_target_group" "application" {
  for_each    = { api = 8000, web = 3000 }
  name        = "${local.name}-${each.key}"
  port        = each.value
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.network.vpc_id

  health_check {
    enabled             = true
    path                = each.key == "api" ? "/health" : "/"
    matcher             = "200"
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}