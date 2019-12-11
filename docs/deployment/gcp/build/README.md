# Google Cloud Build

This example uses [Cloud Build](https://cloud.google.com/cloud-build/) to build the application, upload a WAR file to [Cloud Storage](https://cloud.google.com/storage/), and push a Docker image to [Container Registry](https://cloud.google.com/container-registry/).

## Using Cloud Console

(TODO)

## Using Cloud Shell / SDK

    # Set variables, adjust them as needed
    PROJECT_ID=$(gcloud config get-value project)
    REGION=$(gcloud config get-value compute/region)
    BUCKET_NAME=$PROJECT_ID

    # Create Cloud Storage Bucket
    gsutil mb -l $REGION -p $PROJECT_ID gs://$BUCKET_NAME

    # Clone source and launch Cloud Build
    git clone https://github.com/fcrespel/karaplan.git karaplan
    cd karaplan
    gcloud builds submit .

    # List builds
    gcloud builds list

    # When done, list created Storage objects
    gsutil ls gs://$BUCKET_NAME/karaplan
