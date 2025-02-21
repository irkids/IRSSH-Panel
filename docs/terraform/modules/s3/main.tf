resource "aws_s3_bucket" "main" {
  bucket = var.bucket_name

  tags = {
    Name        = "${var.project}-${var.environment}-bucket"
    Environment = var.environment
    Project     = var.project
  }
}

resource "aws_s3_bucket_versioning" "main" {
  bucket = aws_s3_bucket.main.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_rule" "main" {
  bucket = aws_s3_bucket.main.id

  prefix = "backups/"

  transition {
    days          = 30
    storage_class = "STANDARD_IA"
  }

  transition {
    days          = 60
    storage_class = "GLACIER"
  }

  expiration {
    days = 90
  }
}
