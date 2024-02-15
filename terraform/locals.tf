locals {
  sso_instance_arn = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
}
