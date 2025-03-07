# Terraform for Google Cloud Run

This example uses [Terraform](https://terraform.io) to provision all resources described in the [Google Cloud Run](../../gcp/cloudrun/README.md) guide. See the `main.tf` and `variables.tf` files for more information.

## Configuration

Create a `terraform.tfvars` file in this directory, providing appropriate values for all variables:

```tf
credentials = "/path/to/credentials.json"
project_id = "your-project-id"
region = "europe-west1"
google_oauth_clientid = "toComplete"
google_oauth_clientsecret = "toComplete"
github_oauth_clientid = "toComplete"
github_oauth_clientsecret = "toComplete"
```

See `variables.tf` for more information about available variables.
Refer to the deployment [README](../../README.md) file for information about configuring identity providers.

## Execution

Run the following commands:

```sh
terraform init
terraform plan
```

If everything looks right, execute the following command to provision all resources:

```sh
terraform apply
```

After several minutes, the application should become available at the generated service URL and/or at the custom domain name.

## Architecture diagram

![Architecture](../../gcp/cloudrun/architecture.png)
