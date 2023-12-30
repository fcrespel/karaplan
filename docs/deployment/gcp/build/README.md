# Google Cloud Build

This example uses [Cloud Build](https://cloud.google.com/cloud-build/) to build the application, upload a WAR file to [Cloud Storage](https://cloud.google.com/storage/), and push a Docker image to [Artifact Registry](https://cloud.google.com/artifact-registry/).

## Prerequisites

Before starting, **create a fork** of the project on GitHub (https://github.com/fcrespel/karaplan) under your own account.

## Using Cloud Console

Go to [Cloud Console](https://console.cloud.google.com) and make sure the appropriate project is selected in the header menu.

In the side menu, go to **Cloud Storage > Browser** to prepare the bucket where the WAR file will be stored:
* Click **Create Bucket**.
* Enter your project ID as the bucket **name**, then **Continue**.
* Select **Region** and your preferred region (e.g. `europe-west1`), then **Continue**.
* Click **Create**.
* Click **Create folder**, type `karaplan` and click **Create**.

In the side menu, go to **Artifact Registry** to prepare the repository where the container image will be stored:
* Click **Create Repository**.
* Enter the repository **name** (e.g. `docker`).
* Select **Docker** as the repository **format**.
* Select your preferred **region** (e.g. `europe-west1`).
* Click **Create**.

In the side menu, go to **Cloud Build > Triggers**:
* Click **Manage repositories**, then **Connect repository**.
* Select your preferred region (e.g. `europe-west1`), select **GitHub** and click **Continue**.
* Link your GitHub account, then select `karaplan` in the repository list and click **Connect**.
* Click **Create a trigger**.
* Enter the trigger **name** (e.g. `master`).
* Leave default values and click **Create**.
* Click **Run** to start a build immediately.
* Go to the **History** section of the side menu to see the current build.

When the build is successful, you may check the results in:
* **Cloud Storage > Browser**: in the `karaplan` folder of your bucket, you should now see the `karaplan.war` file.
* **Artifact Registry > Repositories**: a `karaplan` image should be available in the `docker` repository with the `master` tag.

## Using Cloud Shell / SDK

Use the following commands in [Cloud Shell](https://cloud.google.com/shell/) or anywhere the [Cloud SDK](https://cloud.google.com/sdk/) is installed:

    # Set variables, adjust them as needed
    PROJECT_ID=$(gcloud config get-value project)
    REGION=$(gcloud config get-value compute/region)
    BUCKET_NAME=$PROJECT_ID

    # Create Cloud Storage Bucket to store the WAR file
    gsutil mb -l $REGION -p $PROJECT_ID gs://$BUCKET_NAME

    # Create Artifact Registry repository to store the Docker image
    gcloud artifacts repositories create docker --repository-format=docker --location=$REGION

    # Clone source and launch Cloud Build
    git clone https://github.com/fcrespel/karaplan.git karaplan
    cd karaplan
    gcloud builds submit .

    # List builds
    gcloud builds list

    # When done, list created Storage objects and Docker images
    gsutil ls gs://$BUCKET_NAME/karaplan
    gcloud artifacts docker images list $REGION-docker.pkg.dev/$PROJECT_ID/docker/karaplan
