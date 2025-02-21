provider "aws" {
  region = var.aws_region
}

module "vpc" {
  source = "./modules/vpc"
  
  vpc_cidr = var.vpc_cidr
  environment = var.environment
  project = var.project_name
}

module "security_groups" {
  source = "./modules/security_groups"
  
  vpc_id = module.vpc.vpc_id
  environment = var.environment
}

module "ec2" {
  source = "./modules/ec2"
  
  instance_type = var.instance_type
  subnet_ids = module.vpc.private_subnet_ids
  security_group_ids = [module.security_groups.app_sg_id]
  key_name = var.key_name
  environment = var.environment
}

module "rds" {
  source = "./modules/rds"
  
  subnet_ids = module.vpc.private_subnet_ids
  security_group_ids = [module.security_groups.db_sg_id]
  instance_class = var.db_instance_class
  environment = var.environment
}

module "elasticache" {
  source = "./modules/elasticache"
  
  subnet_ids = module.vpc.private_subnet_ids
  security_group
