provider "aws" {
  region = "ap-south-1"
}

resource "aws_s3_bucket" "my_test_bucket" {
  bucket = "my-company-vulnerable-data"
}

resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket = aws_s3_bucket.my_test_bucket.id

  # MISCONFIGURATION: These should be true!
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}