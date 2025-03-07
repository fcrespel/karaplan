# Google Cloud Platform (GCP)

This directory contains specific deployment instructions and examples for [Google Cloud Platform (GCP)](https://cloud.google.com):

1. [**Build**](build/README.md): using [Cloud Build](https://cloud.google.com/cloud-build/) to build and push a WAR file to [Cloud Storage](https://cloud.google.com/storage/), and a Docker image to [Container Registry](https://cloud.google.com/container-registry/).
2. [**SQL**](sql/README.md): using [Cloud SQL](https://cloud.google.com/sql/) to deploy a database for persistence.
3. [**Secret Manager**](secret-manager/README.md): using [Secret Manager](https://cloud.google.com/secret-manager) to store application configuration, including sensitive values.
4. [**GCE Classic**](gce-classic/README.md): using [Compute Engine](https://cloud.google.com/compute/) to run the WAR file with a Tomcat application server in a Managed Instance Group, and [HTTPS Load Balancing](https://cloud.google.com/load-balancing/) to expose the service.
5. [**GCE Container**](gce-container/README.md): using [Compute Engine](https://cloud.google.com/compute/) to run the Docker image in a Managed Instance Group, and [HTTPS Load Balancing](https://cloud.google.com/load-balancing/) to expose the service.
6. [**GKE**](gke/README.md): using [Kubernetes Engine](https://cloud.google.com/kubernetes-engine/) to run the Docker image in a Kubernetes cluster, and an Ingress to expose the service over HTTPS.
7. [**GAE**](gae/README.md): using [App Engine](https://cloud.google.com/appengine/) to run the application and expose the service over HTTPS.
8. [**Cloud Run**](cloudrun/README.md): using [Cloud Run](https://cloud.google.com/run) to run the Docker image and expose the service over HTTPS.
