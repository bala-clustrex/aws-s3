locals {
  project = "clustrex-auth"

  bucket_root_object = "index.html"
}

resource "aws_s3_bucket" "test" {
  bucket = "${local.project}-aws-s3-auth0"
  acl    = "private"

  website {
    index_document = local.bucket_root_object
  }
}

module "aws-s3-auth" {
  source = "../module"

  project = local.project

  s3_bucket_name                = aws_s3_bucket.test.id
  s3_bucket_default_root_object = local.bucket_root_object

  auth0_client_id     = var.auth0_client_id
  auth0_client_secret = var.auth0_client_secret
  auth0_domain        = var.auth0_domain

  // Uncomment the two lines below if you want to use a CUSTOM DOMAIN.
  // You will need to:
  // * Create a CNAME DNS record (example.com in the example below) which points to
  //   module.aws-s3-auth0.cloudfront_distribution_domain_name.
  // * Create an ACM certificate for the domain you want to use (example.com in the example below).
  //cloudfront_alias = "example.com"
  //cloudfront_acm_certificate_arn = "..."

  providers = {
    aws                = aws.us-east-1
    aws.website-bucket = aws
  }
}

// Use this output to allow the redirect URI in your auth0 app.
output "auth0_redirect_uri" {
  value = module.aws-s3-auth.auth0_redirect_uri
}
