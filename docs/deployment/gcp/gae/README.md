# Google App Engine

This example uses [App Engine](https://cloud.google.com/appengine/) to run the application in a completely managed serverless service, with automatic scaling.

## Prerequisites

Before starting, follow the [SQL](../sql) and [Secret Manager](../secret-manager) guides to create the database and configuration.

## Using Cloud Console

Go to [Cloud Console](https://console.cloud.google.com) and make sure the appropriate project is selected in the header menu.

In the side menu, go to **IAM & Admin > Service Accounts**:
* Click **Create Service Account**.
* Set `karaplan` as the Service Account **name** and **ID**.
* Click **Create and continue**.
* Select the following **Roles**:
  * Secret Manager Secret Accessor
  * Cloud SQL Client
* Click **Done**.

In the side menu, go to **App Engine**:
* Click **Create Application**.
* Select your preferred **Region** (e.g. `europe-west`).
* Select the previously created `karaplan` **Service Account**.

If you have a custom domain name:
* From the **Settings** menu, go to the **Custom Domains** tab.
* Click **Add a custom domain**.
* Select your **verified domain** and click **Continue**.
* Enter the **fully-qualified domain name** to use.
* Click **Save mappings**.
* Add the **CNAME record** to your domain as instructed.

Finally, follow the instructions in the *Deploy the application* section below.

## Using Cloud Shell / SDK

Use the following commands in [Cloud Shell](https://cloud.google.com/shell/) or anywhere the [Cloud SDK](https://cloud.google.com/sdk/) is installed:

    # Set variables, adjust them as needed
    PROJECT_ID=$(gcloud config get-value project)
    REGION="europe-west"

    # Create Service Account and grant permissions
    gcloud iam service-accounts create karaplan
    gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:karaplan@$PROJECT_ID.iam.gserviceaccount.com" --role=roles/secretmanager.secretAccessor
    gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:karaplan@$PROJECT_ID.iam.gserviceaccount.com" --role=roles/cloudsql.client

    # Create app in region (warning: can't be changed later!)
    gcloud app create --region=$REGION --service-account=karaplan@$PROJECT_ID.iam.gserviceaccount.com

    # If the app already exists, update the Service Account if necessary
    gcloud app update --service-account=karaplan@$PROJECT_ID.iam.gserviceaccount.com

If you have a custom domain name:

    DOMAIN=your.custom.domain

    # Create domain mapping
    gcloud app domain-mappings create $DOMAIN --certificate-management=AUTOMATIC

    # Add the CNAME record to your domain as instructed.

Finally, follow the instructions in the *Deploy the application* section below.

## Using Terraform

This directory contains a [Terraform](https://terraform.io) module to provision some of the resources automatically. See the `main.tf`, `variables.tf` files for more information.

Please refer to the [Terraform Cloud Run Deployment](../../terraform/gae) guide for a full example.

Finally, follow the instructions in the *Deploy the application* section below.

## Deploy the application

Use the following commands in [Cloud Shell](https://cloud.google.com/shell/) or anywhere the [Cloud SDK](https://cloud.google.com/sdk/) is installed:

    # Get app source code if necessary
    git clone https://github.com/fcrespel/karaplan.git
    cd karaplan

    # Build and deploy app with Maven
    ./mvnw -Dfrontend-build -Dappengine-build -DskipTests package appengine:deploy

After completion, the application should be available at `https://<project-id>.ew.r.appspot.com`
