# Google Cloud Run

This example uses [Cloud Run](https://cloud.google.com/run) to run the Docker image and expose the service.

## Prerequisites

Before starting, follow the [Build](../build), [SQL](../sql) and [Memorystore](../memorystore) guides to create the container image, database and Redis instance.

Then, refer to the deployment [README](../../README.md) file for information about configuring identity providers.

Finally, configure [Serverless VPC Access](https://cloud.google.com/vpc/docs/configure-serverless-vpc-access#creating_a_connector) as described in the official documentation, to allow communication between Cloud Run and the Memorystore (Redis) instance.

## Using Cloud Console

Go to [Cloud Console](https://console.cloud.google.com) and make sure the appropriate project is selected in the header menu.

In the side menu, go to **Serverless > Cloud Run**:
* Click **Create service**.
* Enter `karaplan` as the service **name**.
* Select your preferred **Region** (e.g. `europe-west1`).
* Click **Next**.
* Enter the **Container image name**, e.g. `eu.gcr.io/YOUR_PROJECT_ID/karaplan:master`.
* Click **Advanced settings**.
  * In the **Container** tab, set **Memory allocated** to `1 GiB` and configure **Autoscaling** minimum/maximum numbers of instances (e.g. 0 to 5).
  * In the **Connections** tab, select the appropriate **VPC Connector** to access the Redis instance over the VPC network.
  * In the **Variables and secrets** tab, add the following **Environment variables** (replace `toComplete` with appropriate values):

  | Name | Value |
  | ---- | ----- |
  | SPRING_DATASOURCE_USERNAME | karaplan |
  | SPRING_DATASOURCE_PASSWORD | toComplete |
  | SPRING_DATASOURCE_URL | jdbc:mysql:///toComplete?useSSL=false&socketFactory=com.google.cloud.sql.mysql.SocketFactory&cloudSqlInstance=toComplete |
  | SPRING_JPA_DATABASEPLATFORM | org.hibernate.dialect.MySQL5InnoDBDialect |
  | SPRING_PROFILES_ACTIVE | gcp |
  | SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID | toComplete |
  | SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET | toComplete |
  | SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTID | toComplete |
  | SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTSECRET | toComplete |
  | SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID | toComplete |
  | SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET | toComplete |
  | SPRING_SESSION_STORETYPE | redis |
  | SPRING_REDIS_HOST | toComplete |
  
* Click **Next**.
* Configure **Ingress** to **Allow all traffic** and **Authentication** to **Allow unauthenticated invocations**.
* Click **Create**.

If you have a custom domain name:
* From the Cloud Run services list, click **Manage custom domains**.
* Click **Add mapping**.
* Select the `karaplan` service, your **verified domain** and enter the **subdomain** to use.
* Add the **CNAME record** to your domain as instructed.

After a few minutes, the application should become available at the generated service URL and/or at the custom domain name.

## Using Cloud Shell / SDK

Use the following commands in [Cloud Shell](https://cloud.google.com/shell/) or anywhere the [Cloud SDK](https://cloud.google.com/sdk/) is installed:

    # Set variables, adjust them as needed
    PROJECT_ID=$(gcloud config get-value project)
    REGION=$(gcloud config get-value compute/region)
    VPC_CONNECTOR=toComplete

    # Create environment variables (replace 'toComplete' with appropriate values)
    ENV_VARS="\
    SPRING_DATASOURCE_USERNAME=karaplan,\
    SPRING_DATASOURCE_PASSWORD=toComplete,\
    SPRING_DATASOURCE_URL=jdbc:mysql:///toComplete?useSSL=false&socketFactory=com.google.cloud.sql.mysql.SocketFactory&cloudSqlInstance=$PROJECT_ID:$REGION:toComplete,\
    SPRING_JPA_DATABASEPLATFORM=org.hibernate.dialect.MySQL5InnoDBDialect,\
    SPRING_PROFILES_ACTIVE=gcp,\
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID=toComplete,\
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET=toComplete,\
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTID=toComplete,\
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTSECRET=toComplete,\
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID=toComplete,\
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET=toComplete,\
    SPRING_SESSION_STORETYPE=redis,\
    SPRING_REDIS_HOST=toComplete"

    # Deploy Cloud Run service
    gcloud run deploy karaplan --image eu.gcr.io/$PROJECT_ID/karaplan:master --cpu=1 --memory=1Gi --min-instances=0 --max-instances=5 --allow-unauthenticated --vpc-connector=$VPC_CONNECTOR --region=$REGION --set-env-vars="$ENV_VARS"

If you have a custom domain name:

    DOMAIN=your.custom.domain

    # Create domain mapping
    gcloud beta run domain-mappings create --service=karaplan --domain=$DOMAIN --region=$REGION

    # Add the CNAME record to your domain as instructed.

After a few minutes, the application should become available at the generated service URL and/or at the custom domain name.

## Using Terraform

This directory contains a [Terraform](https://terraform.io) module to provision all resources automatically. See the `main.tf`, `variables.tf` and `outputs.tf` files for more information.

Please refer to the [Terraform Cloud Run Deployment](../../terraform/cloudrun) guide for a full example.

## Architecture diagram

![Architecture](architecture.png)
