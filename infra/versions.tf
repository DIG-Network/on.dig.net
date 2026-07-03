terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # Remote state in the shared dig.net S3 state bucket (one key per service). Filled in via
  # -backend-config at init time so `terraform validate` works offline:
  #   terraform init \
  #     -backend-config="bucket=dighub-tfstate" \
  #     -backend-config="dynamodb_table=dighub-tflock" \
  #     -backend-config="region=us-east-1"
  backend "s3" {
    key     = "on.dig.net/prod/terraform.tfstate"
    encrypt = true
  }
}

# CloudFront + its ACM cert live in us-east-1, and the shared dighub table + DynamoDB are there too,
# so this whole stack is single-region us-east-1.
provider "aws" {
  region = var.region
  default_tags {
    tags = {
      project = "on-dig-net"
      service = "resolver"
      env     = var.environment
    }
  }
}
