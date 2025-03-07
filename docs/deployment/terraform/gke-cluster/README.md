# Terraform for Google Kubernetes Engine Cluster

This example uses [Terraform](https://terraform.io) to provision a Google Kubernetes Engine (GKE) cluster. See the `main.tf` and `variables.tf` files for more information.

## Configuration

Create a `terraform.tfvars` file in this directory, providing appropriate values for all variables:

```tf
credentials = "/path/to/credentials.json"
project_id = "your-project-id"
region = "europe-west1"
```

See `variables.tf` for more information about available variables.

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

After several minutes, the GKE cluster should be up and running.

To deploy the application on it, see the [GKE Deployment](../gke/README.md) guide.
