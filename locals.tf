locals {
  name = "${var.cluster_name}-${random_id.suffix.hex}"

  common_tags = merge(
    var.tags,
    {
      Name        = "test"
      Environment = "dev"
      Project     = "test"
    }
  )
}
