# Google Cloud Run

This example uses [Cloud Run](https://cloud.google.com/run) to run the Docker image and expose the service.

## Prerequisites

Before starting, follow the [Build](../build) and [SQL](../sql) guides to create the container image and database.

Then, refer to the deployment [README](../../README.md) file for information about configuring identity providers.

## Using Cloud Console

Go to [Cloud Console](https://console.cloud.google.com) and make sure the appropriate project is selected in the header menu.

In the side menu, go to **Cloud Run**:
* Click **Create service**.
* Enter the **Container image name**, e.g. `europe-west1-docker.pkg.dev/YOUR_PROJECT_ID/docker/karaplan:master`.
* Enter `karaplan` as the service **name**.
* Select your preferred **Region** (e.g. `europe-west1`).
* Configure the **maximum number of instances** (e.g. `5`).
* Select **Allow unauthenticated invocations**.
* Expand additional settings at the bottom.
  * In the **Container** tab, set **Memory** to `1 GiB`.
  * In the **Variables and secrets** tab, add the following **Environment variables** (replace `toComplete` with appropriate values):

  | Name | Value |
  | ---- | ----- |
  | SPRING_DATASOURCE_USERNAME | karaplan |
  | SPRING_DATASOURCE_PASSWORD | toComplete |
  | SPRING_DATASOURCE_URL | jdbc:mysql:///karaplan?useSSL=false&socketFactory=com.google.cloud.sql.mysql.SocketFactory&cloudSqlInstance=toComplete |
  | SPRING_PROFILES_ACTIVE | gcp |
  | SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID | toComplete |
  | SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET | toComplete |
  | SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTID | toComplete |
  | SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTSECRET | toComplete |
  | SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID | toComplete |
  | SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET | toComplete |

* Click **Create**.

If you have a custom domain name:
* From the Cloud Run services list, click **Manage custom domains**.
* Click **Add mapping**.
* Select the `karaplan` service and **Cloud Run Domain Mappings**.
* Select your **verified domain** and enter the **subdomain** to use.
* Add the **CNAME record** to your domain as instructed.

After a few minutes, the application should become available at the generated service URL and/or at the custom domain name.

## Using Cloud Shell / SDK

Use the following commands in [Cloud Shell](https://cloud.google.com/shell/) or anywhere the [Cloud SDK](https://cloud.google.com/sdk/) is installed:

    # Set variables, adjust them as needed
    PROJECT_ID=$(gcloud config get-value project)
    REGION=$(gcloud config get-value compute/region)

    # Create environment variables (replace 'toComplete' with appropriate values)
    ENV_VARS="\
    SPRING_DATASOURCE_USERNAME=karaplan,\
    SPRING_DATASOURCE_PASSWORD=toComplete,\
    SPRING_DATASOURCE_URL=jdbc:mysql:///karaplan?useSSL=false&socketFactory=com.google.cloud.sql.mysql.SocketFactory&cloudSqlInstance=$PROJECT_ID:$REGION:toComplete,\
    SPRING_PROFILES_ACTIVE=gcp,\
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID=toComplete,\
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET=toComplete,\
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTID=toComplete,\
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTSECRET=toComplete,\
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID=toComplete,\
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET=toComplete

    # Deploy Cloud Run service
    gcloud run deploy karaplan --image $REGION-docker.pkg.dev/$PROJECT_ID/docker/karaplan:master --cpu=1 --memory=1Gi --min-instances=0 --max-instances=5 --allow-unauthenticated --region=$REGION --set-env-vars="$ENV_VARS"

If you have a custom domain name:

    DOMAIN=your.custom.domain

    # Create domain mapping
    gcloud run domain-mappings create --service=karaplan --domain=$DOMAIN --region=$REGION

    # Add the CNAME record to your domain as instructed.

After a few minutes, the application should become available at the generated service URL and/or at the custom domain name.

## Using Terraform

This directory contains a [Terraform](https://terraform.io) module to provision all resources automatically. See the `main.tf`, `variables.tf` and `outputs.tf` files for more information.

Please refer to the [Terraform Cloud Run Deployment](../../terraform/cloudrun) guide for a full example.

## Architecture diagram

![Architecture](architecture.png)
