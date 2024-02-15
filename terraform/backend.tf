# Variable use is not allowed, must be hard-coded to the account you want to apply to
terraform {
  backend "s3" {
    encrypt = "true"
    bucket  = "117849881269-tf-remote-state" # TODO UPDATE TO MATCH YOUR TF INFRASTRUCTURE
    # dynamodb_table = "tf-state-lock"                # UPDATE TO MATCH YOUR TF INFRASTRUCTURE
    key     = "single-stage-aws-iam-identity-center-pipeline.tfstate"
    region  = "us-west-2" # "YOUR_REGION_HERE" # UPDATE IF YOU USE A DIFFERENT REGION
    profile = ""          # Removed profile so that pipelines don't look for a nonexistent profile
  }
}
