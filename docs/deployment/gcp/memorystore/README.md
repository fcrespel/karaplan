# Google Cloud Memorystore

This example uses [Cloud Memorystore](https://cloud.google.com/memorystore/) to deploy a Redis instance for distributed caching.

It can then be used for sharing sessions across multiple instances of the application, as an alternative to sticky sessions.

## Using Cloud Console

Go to [Cloud Console](https://console.cloud.google.com) and make sure the appropriate project is selected in the header menu.

In the side menu, go to **Memorystore**:
* Click **Create instance**.
* Choose an **Instance ID** such as `karaplan-redis`.
* Choose a **Region** (e.g. `europe-west1`).
* Click **Create**.

Take note of the **IP address** for use during application deployment.

## Using Cloud Shell / SDK

Use the following commands in [Cloud Shell](https://cloud.google.com/shell/) or anywhere the [Cloud SDK](https://cloud.google.com/sdk/) is installed:

    # Set variables, adjust them as needed
    REGION=$(gcloud config get-value compute/region)

    # Create Redis instance (takes some time)
    gcloud redis instances create karaplan-redis --region=$REGION

Take note of the **IP address** for use during application deployment.

## Using Terraform

This directory contains a [Terraform](https://terraform.io) module to provision all resources automatically. See the `main.tf`, `variables.tf` and `outputs.tf` files for more information.

Please refer to the [Terraform](../terraform) guide for a full example.
