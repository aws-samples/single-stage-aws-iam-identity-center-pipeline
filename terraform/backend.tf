# Variable use is not allowed, must be hard-coded to the account you want to apply to
terraform {
  backend "s3" {
    encrypt        = "true"
    bucket         = "<YOUR_ACCOUNT_ID>-tf-remote-state" #  UPDATE TO MATCH YOUR TF INFRASTRUCTURE
    dynamodb_table = "tf-state-lock"                     # UPDATE TO MATCH YOUR TF INFRASTRUCTURE
    key            = "single-stage-aws-iam-identity-center-pipeline.tfstate"
    region         = "YOUR_REGION_HERE" # UPDATE IF YOU USE A DIFFERENT REGION
  }
}
