provider "aws" {
  default_tags {
    tags = {
      "sso_pipeline" = "true"
    }
  }
  region = var.region
}

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}
