# Google Compute Engine - Container deployment

This example uses [Compute Engine](https://cloud.google.com/compute/) to run the Docker image in a Managed Instance Group, and [HTTPS Load Balancing](https://cloud.google.com/load-balancing/) to expose the service.

## Prerequisites

Before starting, follow the [Build](../build) and [SQL](../sql) guides to create the container image and database.

Then, refer to the deployment [README](../../README.md) file for information about configuring identity providers.

Finally, to expose the application over HTTPS, you will need to obtain a **domain name** in which you can create a **A record** pointing to a reserved IP address. If you don't have one, you may try using services from [sslip.io](https://sslip.io), [nip.io](https://nip.io) or [xip.io](http://xip.io).

## Using Cloud Console

Go to [Cloud Console](https://console.cloud.google.com) and make sure the appropriate project is selected in the header menu.

In the side menu, go to **Compute > Instance templates**:
* Click **Create instance template**.
* Enter `karaplan-container-template-1` as the template **name**.
* Leave the default **Machine type** as `n1-standard-1`.
* Check **Deploy a container image to this VM instance** and enter the container image name, e.g. `eu.gcr.io/YOUR_PROJECT_ID/karaplan:master`, or the official image `fcrespel/karaplan:master`.
* Expand the advanced container options just below.
* Add the following **Environment variables** (replace `toComplete` with appropriate values):

| Name | Value |
| ---- | ----- |
| SPRING_DATASOURCE_USERNAME | karaplan |
| SPRING_DATASOURCE_PASSWORD | toComplete |
| SPRING_DATASOURCE_URL | jdbc:mysql://toComplete/karaplan?useSSL | false |
| SPRING_JPA_DATABASEPLATFORM | org.hibernate.dialect.MySQL5InnoDBDialect |
| SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID | toComplete |
| SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET | toComplete |
| SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTID | toComplete |
| SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTSECRET | toComplete |
| SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID | toComplete |
| SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET | toComplete |

* Click **Create**.

In the side menu, go to **Compute > Instance groups**:
* Click **Create instance group**.
* Enter `karaplan-container-ig` as the group name.
* Select **Multiple zones** as the **Location**, then select your preferred **Region** (e.g. `europe-west1`).
* Select `karaplan-container-template-1` as the **Instance template**.
* Set **Autoscaling** to **Off**, and set **Number of instances** to **3**.
* Click **Create**.

In the side menu, go to **Network services > Load balancing**:
* Click **Create load balancer**
* Under **HTTP(S) Load Balancing**, click **Start configuration**.
* Select **From Internet to my VMs**, then click **Continue**.
* Enter `karaplan-container-lb` as the load balancer **name**.
* In **Backend configuration**, click the dropdown menu to select **Backend services > Create a backend service**.
  * Enter `karaplan-container-bes` as the backend service **name**.
  * Select `karaplan-container-ig` as the **Instance group**, `8080` as the port number, then click **Done**.
  * In **Health check**, click **Create a health check** 
    * Enter `karaplan-container-hc` as the health check **name**.
    * Select **HTTP** as the **Protocol**, and `8080` as the port number.
    * Enter `/actuator/health` as the **Request path**.
  * Expand the configuration options at the bottom.
  * Select **Generated cookie** as the **Session affinity**.
  * Click **Create**.
* In **Frontend configuration**:
  * Enter `karaplan-container-frontend` as the frontend service **name**.
  * In the **IP Address** dropdown, **Create IP address** named `karaplan-container-ip`.
  * If you *don't* have a custom domain name, leave **HTTP** as the **Protocol**.
  * If you *do* have a custom domain name:
    * Select **HTTPS** as the **Protocol**.
    * In the **Certificate** dropdown, **Create a new certificate** named `karaplan-container-ssl-cert` for your custom domain name.
  * Click **Done**.
* Click **Create**.

When the loadbalancer is created, click on it to reveal its **IP address**.
If you have a custom domain name, add this IP address in a **A record**.

After several minutes, the application should become available at this IP address and/or at the custom domain name.

## Using Cloud Shell / SDK

Use the following commands in [Cloud Shell](https://cloud.google.com/shell/) or anywhere the [Cloud SDK](https://cloud.google.com/sdk/) is installed:

    # Set variables, adjust them as needed
    PROJECT_ID=$(gcloud config get-value project)
    REGION=$(gcloud config get-value compute/region)

    # Create environment variables (replace 'toComplete' with appropriate values)
    cat - > karaplan.env <<EOF
    SPRING_DATASOURCE_USERNAME=karaplan
    SPRING_DATASOURCE_PASSWORD=toComplete
    SPRING_DATASOURCE_URL=jdbc:mysql://toComplete/karaplan?useSSL=false
    SPRING_JPA_DATABASEPLATFORM=org.hibernate.dialect.MySQL5InnoDBDialect
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID=toComplete
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET=toComplete
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTID=toComplete
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTSECRET=toComplete
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID=toComplete
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET=toComplete
    EOF

    # Create Instance template
    gcloud compute instance-templates create-with-container karaplan-container-template-1 --machine-type=n1-standard-1 --image=cos-stable-78-12499-59-0 --image-project=cos-cloud --boot-disk-size=10GB --boot-disk-type=pd-standard --container-image=eu.gcr.io/$PROJECT_ID/karaplan:master --container-env-file=karaplan.env

    # Create Instance group
    gcloud compute instance-groups managed create karaplan-container-ig --size=3 --template=karaplan-container-template-1 --region=$REGION
    gcloud compute instance-groups managed set-named-ports karaplan-container-ig --named-ports=http:8080 --region=$REGION

    # Create HTTP health check
    gcloud compute health-checks create http karaplan-container-hc --port=8080 --request-path=/actuator/health

    # Create Backend service
    gcloud compute backend-services create karaplan-container-bes --global --load-balancing-scheme=EXTERNAL --health-checks=karaplan-container-hc --port-name=http --protocol=HTTP --session-affinity=GENERATED_COOKIE --affinity-cookie-ttl=0

    # Create URL map
    gcloud compute url-maps create karaplan-container-url-map --default-service=karaplan-container-bes

    # Create IP address
    gcloud compute addresses create karaplan-container-ip --global
    gcloud compute addresses list

If you *don't* have a custom domain name:

    # Create Target HTTP proxy
    gcloud compute target-http-proxies create karaplan-container-http-proxy --url-map=karaplan-container-url-map

    # Create Forwarding rule
    gcloud compute forwarding-rules create karaplan-container-fwd-http --global --load-balancing-scheme=EXTERNAL --target-http-proxy=karaplan-container-http-proxy --global-address --address=karaplan-container-ip --ports=80

If you *do* have a custom domain name, add the created IP address in a **A record**, then:

    DOMAIN=your.custom.domain

    # Create SSL certificate
    gcloud beta compute ssl-certificates create karaplan-container-ssl-cert --domains=$DOMAIN --global

    # Create Target HTTPS proxy
    gcloud compute target-https-proxies create karaplan-container-https-proxy --ssl-certificates=karaplan-container-ssl-cert --url-map=karaplan-container-url-map

    # Create Forwarding rule
    gcloud compute forwarding-rules create karaplan-container-fwd-https --global --load-balancing-scheme=EXTERNAL --target-https-proxy=karaplan-container-https-proxy --global-address --address=karaplan-container-ip --ports=443

After several minutes, the application should become available at this IP address and/or at the custom domain name.

## Using Terraform

You may use [Terraform](https://terraform.io) to provision all resources automatically. See the `main.tf` and `variables.tf` files for more information.

First create a `terraform.tfvars` file in this directory, providing appropriate values for all variables:

    credentials = "/path/to/credentials.json"
    project_id = "your-project-id"
    region = "europe-west1"
    zones = ["europe-west1-b", "europe-west1-c", "europe-west1-d"]
    domain_name = "your.custom.domain"
    https_enabled = true
    instances_count = 3
    db_password = "toComplete"
    db_address = "host:port"
    google_oauth_clientid = "toComplete"
    google_oauth_clientsecret = "toComplete"
    facebook_oauth_clientid = "toComplete"
    facebook_oauth_clientsecret = "toComplete"
    github_oauth_clientid = "toComplete"
    github_oauth_clientsecret = "toComplete"

Then, run the following commands:

    terraform init
    terraform apply

After several minutes, the application should become available at the reserved IP address and/or at the custom domain name.
