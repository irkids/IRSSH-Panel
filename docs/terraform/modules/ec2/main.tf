resource "aws_instance" "app" {
  count                  = var.instance_count
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_ids[count.index % length(var.subnet_ids)]
  vpc_security_group_ids = var.security_group_ids
  key_name              = var.key_name
  iam_instance_profile  = aws_iam_instance_profile.app.name

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_size
    encrypted   = true
  }

  user_data = templatefile("${path.module}/user_data.sh", {
    environment = var.environment
    region      = var.aws_region
  })

  tags = {
    Name        = "${var.project}-${var.environment}-app-${count.index + 1}"
    Environment = var.environment
    Project     = var.project
  }
}

resource "aws_iam_role" "app" {
  name = "${var.project}-${var.environment}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.project}-${var.environment}-app-profile"
  role = aws_iam_role.app.name
}

resource "aws_iam_role_policy_attachment" "app_policy" {
  for_each = var.iam_policy_arns

  role       = aws_iam_role.app.name
  policy_arn = each.value
}
