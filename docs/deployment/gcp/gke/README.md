# Google Kubernetes Engine

This example uses [Kubernetes Engine](https://cloud.google.com/kubernetes-engine/) to run the Docker image in a Kubernetes cluster, and an Ingress to expose the service over HTTPS.

## Using Cloud Console

Go to [Cloud Console](https://console.cloud.google.com) and make sure the appropriate project is selected in the header menu.

(TODO)

## Using Cloud Shell / SDK

Use the following commands in [Cloud Shell](https://cloud.google.com/shell/) or anywhere the [Cloud SDK](https://cloud.google.com/sdk/) is installed:

    # Set variables, adjust them as needed
    PROJECT_ID=$(gcloud config get-value project)
    REGION=$(gcloud config get-value compute/region)

    (TODO)
