resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.project}-${var.environment}-cache-subnet-group"
  subnet_ids = var.subnet_ids
}

resource "aws_elasticache_parameter_group" "main" {
  family = "redis6.x"
  name   = "${var.project}-${var.environment}-cache-params"

  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id          = "${var.project}-${var.environment}-cache"
  replication_group_description = "Redis cluster for ${var.project}-${var.environment}"
  node_type                     = var.node_type
  number_cache_clusters         = var.environment == "production" ? 2 : 1
  port                          = 6379

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = var.security_group_ids

  automatic_failover_enabled = var.environment == "production"
  multi_az_enabled          = var.environment == "production"

  parameter_group_name = aws_elasticache_parameter_group.main.name
  engine_version      = "6.x"

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  maintenance_window = var.maintenance_window
  snapshot_window   = var.snapshot_window

  tags = {
    Name        = "${var.project}-${var.environment}-cache"
    Environment = var.environment
    Project     = var.project
  }
}
