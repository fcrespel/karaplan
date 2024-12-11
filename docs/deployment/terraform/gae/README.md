# Terraform for Google App Engine

This example uses [Terraform](https://terraform.io) to provision some of the resources described in the [Google App Engine](../../gcp/gae) guide. See the `main.tf` and `variables.tf` files for more information.

## Configuration

Create a `terraform.tfvars` file in this directory, providing appropriate values for all variables:

    credentials = "/path/to/credentials.json"
    project_id = "your-project-id"
    region = "europe-west1"
    google_oauth_clientid = "toComplete"
    google_oauth_clientsecret = "toComplete"
    github_oauth_clientid = "toComplete"
    github_oauth_clientsecret = "toComplete"

See `variables.tf` for more information about available variables.
Refer to the deployment [README](../../README.md) file for information about configuring identity providers.

## Execution

Run the following commands:

    terraform init
    terraform plan

If everything looks right, execute the following command to provision all resources:

    terraform apply

Additional steps are required to deploy the application itself. Please refer to the *Deploy the application* section of the [Google App Engine](../../gcp/gae) guide.
