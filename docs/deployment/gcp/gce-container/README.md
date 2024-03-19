# Google Compute Engine - Container deployment

This example uses [Compute Engine](https://cloud.google.com/compute/) to run the Docker image in a Managed Instance Group, and [HTTPS Load Balancing](https://cloud.google.com/load-balancing/) to expose the service.

## Prerequisites

Before starting, follow the [Build](../build), [SQL](../sql) and [Secret Manager](../secret-manager) guides to create the container image, database and configuration.

Finally, to expose the application over HTTPS, you will need to obtain a **domain name** in which you can create a **A record** pointing to a reserved IP address. If you don't have one, you may try using services from [sslip.io](https://sslip.io), [nip.io](https://nip.io) or [xip.io](http://xip.io).

## Using Cloud Console

Go to [Cloud Console](https://console.cloud.google.com) and make sure the appropriate project is selected in the header menu.

In the side menu, go to **IAM & Admin > Service Accounts**:
* Click **Create Service Account**.
* Set `karaplan` as the Service Account **name** and **ID**.
* Click **Create and continue**.
* Select the following **Roles**:
  * Logs Writer
  * Monitoring Metric Writer
  * Secret Manager Secret Accessor
  * Cloud SQL Client
* Click **Done**.

In the side menu, go to **Compute Engine > Instance templates**:
* Click **Create instance template**.
* Enter `karaplan-container-template-1` as the template **name**.
* Select `e2-medium` as the **Machine type**.
* Click **Deploy container**
* Enter the container image name, e.g. `europe-west1-docker.pkg.dev/YOUR_PROJECT_ID/docker/karaplan:master`, or the official image `ghcr.io/fcrespel/karaplan:master`.
* Add a `SPRING_PROFILES_ACTIVE` **Environment variable** with value `gcp`.
* Click **Select**.
* Select the previously created `karaplan` **Service Account**.
* Select **Allow full access to all Cloud APIs** under **Access scopes**.
* Click **Create**.

In the side menu, go to **Compute Engine > Instance groups**:
* Click **Create instance group**.
* Enter `karaplan-container-ig` as the group name.
* Select `karaplan-container-template-1` as the **Instance template**.
* Select **Multiple zones** as the **Location**, then select your preferred **Region** (e.g. `europe-west1`).
* Set **Autoscaling** to **Off**, and set **Number of instances** to **3**.
* Click **Create**.

In the side menu, go to **Network services > Load balancing**:
* Click **Create load balancer**
* Under **Application Load Balancer (HTTP/S)**, click **Start configuration**.
* Select **From Internet to my VMs**, then click **Continue**.
* Enter `karaplan-container-lb` as the load balancer **name**.
* In **Frontend configuration**:
  * Enter `karaplan-container-frontend` as the frontend service **name**.
  * In the **IP Address** dropdown, **Create IP address** named `karaplan-container-ip`.
  * If you *don't* have a custom domain name, leave **HTTP** as the **Protocol**.
  * If you *do* have a custom domain name:
    * Select **HTTPS** as the **Protocol**.
    * In the **Certificate** dropdown, **Create a new certificate** named `karaplan-container-ssl-cert` for your custom domain name.
  * Click **Done**.
* In **Backend configuration**, click the dropdown menu to select **Create a backend service**.
  * Enter `karaplan-container-bes` as the backend service **name**.
  * Select `karaplan-container-ig` as the **Instance group**, `8080` as the port number, then click **Done**.
  * Uncheck **Enable Cloud CDN**.
  * In **Health check**, click **Create a health check** 
    * Enter `karaplan-container-hc` as the health check **name**.
    * Select **HTTP** as the **Protocol**, and `8080` as the port number.
    * Enter `/actuator/health/readiness` as the **Request path**.
  * Click **Create**.
* Click **Create**.

When the loadbalancer is created, click on it to reveal its **IP address**.
If you have a custom domain name, add this IP address in a **A record**.

After several minutes, the application should become available at this IP address and/or at the custom domain name.

## Using Cloud Shell / SDK

Use the following commands in [Cloud Shell](https://cloud.google.com/shell/) or anywhere the [Cloud SDK](https://cloud.google.com/sdk/) is installed:

    # Set variables, adjust them as needed
    PROJECT_ID=$(gcloud config get-value project)
    REGION=$(gcloud config get-value compute/region)

    # Create Service Account and grant permissions
    gcloud iam service-accounts create karaplan
    gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:karaplan@$PROJECT_ID.iam.gserviceaccount.com" --role=roles/logging.logWriter
    gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:karaplan@$PROJECT_ID.iam.gserviceaccount.com" --role=roles/monitoring.metricWriter
    gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:karaplan@$PROJECT_ID.iam.gserviceaccount.com" --role=roles/secretmanager.secretAccessor
    gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:karaplan@$PROJECT_ID.iam.gserviceaccount.com" --role=roles/cloudsql.client

    # Create Instance template
    gcloud compute instance-templates create-with-container karaplan-container-template-1 --machine-type=e2-medium --image-family=cos-stable --image-project=cos-cloud --boot-disk-size=10GB --boot-disk-type=pd-standard --container-image=$REGION-docker.pkg.dev/$PROJECT_ID/docker/karaplan:master --container-env="SPRING_PROFILES_ACTIVE=gcp" --service-account=karaplan@$PROJECT_ID.iam.gserviceaccount.com --scopes=https://www.googleapis.com/auth/cloud-platform

    # Create Instance group
    gcloud compute instance-groups managed create karaplan-container-ig --size=3 --template=karaplan-container-template-1 --region=$REGION
    gcloud compute instance-groups managed set-named-ports karaplan-container-ig --named-ports=http:8080 --region=$REGION

    # Create HTTP health check
    gcloud compute health-checks create http karaplan-container-hc --port=8080 --request-path=/actuator/health/readiness

    # Create Backend service
    gcloud compute backend-services create karaplan-container-bes --global --load-balancing-scheme=EXTERNAL_MANAGED --health-checks=karaplan-container-hc --port-name=http --protocol=HTTP
    gcloud compute backend-services add-backend karaplan-container-bes --global --instance-group=karaplan-container-ig --instance-group-region=$REGION

    # Create URL map
    gcloud compute url-maps create karaplan-container-url-map --default-service=karaplan-container-bes

    # Create IP address
    gcloud compute addresses create karaplan-container-ip --global
    gcloud compute addresses list

If you *don't* have a custom domain name:

    # Create Target HTTP proxy
    gcloud compute target-http-proxies create karaplan-container-http-proxy --url-map=karaplan-container-url-map

    # Create Forwarding rule
    gcloud compute forwarding-rules create karaplan-container-fwd-http --global --load-balancing-scheme=EXTERNAL_MANAGED --target-http-proxy=karaplan-container-http-proxy --global-address --address=karaplan-container-ip --ports=80

If you *do* have a custom domain name, add the created IP address in a **A record**, then:

    DOMAIN=your.custom.domain

    # Create SSL certificate
    gcloud compute ssl-certificates create karaplan-container-ssl-cert --domains=$DOMAIN --global

    # Create Target HTTPS proxy
    gcloud compute target-https-proxies create karaplan-container-https-proxy --ssl-certificates=karaplan-container-ssl-cert --url-map=karaplan-container-url-map

    # Create Forwarding rule
    gcloud compute forwarding-rules create karaplan-container-fwd-https --global --load-balancing-scheme=EXTERNAL_MANAGED --target-https-proxy=karaplan-container-https-proxy --global-address --address=karaplan-container-ip --ports=443

After several minutes, the application should become available at this IP address and/or at the custom domain name.

## Using Terraform

This directory contains a [Terraform](https://terraform.io) module to provision all resources automatically. See the `main.tf`, `variables.tf` and `outputs.tf` files for more information.

Please refer to the [Terraform GCE Container Deployment](../../terraform/gce-container) guide for a full example.

## Architecture diagram

![Architecture](architecture.png)
