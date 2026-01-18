locals {
  name         = "${var.cluster_name}-${random_id.suffix.hex}"
  cluster_name = var.cluster_name
  region       = var.region

  common_tags = merge(
    var.tags,
    {
      Name        = "test"
      Environment = "dev"
      Project     = "test"
    }
  )
}
