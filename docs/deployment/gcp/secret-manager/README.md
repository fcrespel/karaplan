# Google Secret Manager

This example uses [Secret Manager](https://cloud.google.com/secret-manager) to store application configuration, including sensitive values.

Refer to the deployment [README](../../README.md) file for information about configuring identity providers.

## Using Cloud Console

Go to [Cloud Console](https://console.cloud.google.com) and make sure the appropriate project is selected in the header menu.

In the side menu, go to **Security > Secret Manager**:
* Click **Create secret** and fill the **Name** and **Secret value** for the following secrets:
  * karaplan-db-instance
  * karaplan-db-name
  * karaplan-db-username
  * karaplan-db-password
  * karaplan-google-client-id
  * karaplan-google-client-secret
  * karaplan-github-client-id
  * karaplan-github-client-secret
  * karaplan-facebook-client-id
  * karaplan-facebook-client-secret
* Check **Manually manage locations for this secret** and select your preferred **Region** (e.g. `europe-west1`).

## Using Cloud Shell / SDK

Use the following commands in [Cloud Shell](https://cloud.google.com/shell/) or anywhere the [Cloud SDK](https://cloud.google.com/sdk/) is installed:

    # Set variables, adjust them as needed
    REGION=$(gcloud config get-value compute/region)

    # Create each secret (replace 'toComplete' with the actual value)
    echo "toComplete" | gcloud secrets create karaplan-db-instance --data-file=- --replication-policy=user-managed --locations=$REGION
    echo "toComplete" | gcloud secrets create karaplan-db-name --data-file=- --replication-policy=user-managed --locations=$REGION
    echo "toComplete" | gcloud secrets create karaplan-db-username --data-file=- --replication-policy=user-managed --locations=$REGION
    echo "toComplete" | gcloud secrets create karaplan-db-password --data-file=- --replication-policy=user-managed --locations=$REGION
    echo "toComplete" | gcloud secrets create karaplan-google-client-id --data-file=- --replication-policy=user-managed --locations=$REGION
    echo "toComplete" | gcloud secrets create karaplan-google-client-secret --data-file=- --replication-policy=user-managed --locations=$REGION
    echo "toComplete" | gcloud secrets create karaplan-github-client-id --data-file=- --replication-policy=user-managed --locations=$REGION
    echo "toComplete" | gcloud secrets create karaplan-github-client-secret --data-file=- --replication-policy=user-managed --locations=$REGION
    echo "toComplete" | gcloud secrets create karaplan-facebook-client-id --data-file=- --replication-policy=user-managed --locations=$REGION
    echo "toComplete" | gcloud secrets create karaplan-facebook-client-secret --data-file=- --replication-policy=user-managed --locations=$REGION

## Using Terraform

This directory contains a [Terraform](https://terraform.io) module to provision all resources automatically. See the `main.tf` and `variables.tf` files for more information.

Please refer to the [Terraform](../terraform) guide for a full example.
