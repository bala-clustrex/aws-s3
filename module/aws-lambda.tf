resource "local_file" "auth_lambda_file" {
  filename = "${path.module}/auth_lambda_package/auth.js"

  content = templatefile("${path.module}/auth.js.tpl", {
    ssm_param_name_jwt_secret = aws_ssm_parameter.jwt_secret.name,

    ssm_param_name_okta_client_id     = aws_ssm_parameter.okta_client_id.name,
    ssm_param_name_okta_client_secret = aws_ssm_parameter.okta_client_secret.name,
    ssm_param_name_okta_domain        = aws_ssm_parameter.okta_domain.name,

    ssm_param_name_auth_cookie_name    = aws_ssm_parameter.auth_cookie_name.name,
    ssm_param_name_auth_cookie_ttl_sec = aws_ssm_parameter.auth_cookie_ttl_sec.name
  })
}

data "archive_file" "auth_lambda_package" {
  type        = "zip"
  source_dir  = "${path.module}/auth_lambda_package"
  output_path = "${path.module}/auth.zip"

  depends_on = [local_file.auth_lambda_file]
}
resource "aws_lambda_function" "auth" {
  function_name = "${local.project}-auth"
  role          = aws_iam_role.auth_lambda.arn

  filename         = data.archive_file.auth_lambda_package.output_path
  source_code_hash = data.archive_file.auth_lambda_package.output_base64sha256

  runtime = "nodejs12.x"
  handler = "auth.auth"

  publish = true
}
