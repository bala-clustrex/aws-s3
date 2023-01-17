locals {
  project = "${var.project}-s3-auth0"

  s3_origin_id = local.project
}

variable "project" {
  description = "Name of the project which uses this module. Resource names will be prefixed with this value."
}

variable "s3_bucket_name" {
  description = "Name of the existing S3 bucket to protect."
}

variable "s3_bucket_default_root_object" {
  description = "Default object to serve when no path is specified in the request."
}

variable "cloudfront_alias" {
  description = "Alias (domain or subdomain name) that can be used to access the S3 static website bucket."
  default     = ""
}

variable "cloudfront_acm_certificate_arn" {
  description = "ARN of the ACM certificate to use if cloudfront_alias is set."
  default     = ""
}

variable "auth0_client_id" {
  description = "auth0 client ID"
}

variable "auth0_client_secret" {
  description = "auth0 client secret"
}

variable "auth0_domain" {
  description = "auth0 domain"
}

variable "auth_cookie_name" {
  description = "Name of the authentication cookie (default: {var.project}-s3-auth0)."
  default     = ""
}

variable "auth_cookie_ttl_sec" {
  description = "TTL (in seconds) of the authentication cookie."
  default     = 3600
}
