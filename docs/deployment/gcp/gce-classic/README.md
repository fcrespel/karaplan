# Google Compute Engine - Classic deployment

This example uses [Compute Engine](https://cloud.google.com/compute/) to run the WAR file with a Tomcat application server in a Managed Instance Group, and [HTTPS Load Balancing](https://cloud.google.com/load-balancing/) to expose the service.

## Prerequisites

Before starting, follow the [Build](../build) and [SQL](../sql) guides to create the WAR file and database.

Then, download the `karaplan-startup.sh` file available in this directory to your computer. Update the fields marked `toComplete` with appropriate values using your preferred editor.

In the side menu, go to **Storage > Browser**:
* Select your bucket and enter the `karaplan` folder.
* Click **Upload file** and select the `karaplan-startup.sh` file.

Finally, to expose the application over HTTPS, you will need to obtain a **domain name** in which you can create a **A record** pointing to a reserved IP address.

## Using Cloud Console

Go to [Cloud Console](https://console.cloud.google.com) and make sure the appropriate project is selected in the header menu.

In the side menu, go to **Compute > Instance templates**:
* Click **Create instance template**.
* Enter `karaplan-classic-template-1` as the template **name**.
* Leave the default **Machine type** as `n1-standard-1` and distribution as **Debian GNU/Linux 9 (stretch)**.
* Expand the configuration options at the bottom.
* In the **Management > Automation > Metadata** section, enter `startup-script-url` as the key and `gs://YOUR_BUCKET_NAME/karaplan/karaplan-startup.sh` as the value (replace `YOUR_BUCKET_NAME` as needed).
* Click **Create**.

In the side menu, go to **Compute > Instance groups**:
* Click **Create instance group**.
* Enter `karaplan-classic-ig` as the group name.
* Select **Multiple zones** as the **Location**, then select your preferred **Region** (e.g. `europe-west1`).
* Select `karaplan-classic-template-1` as the **Instance template**.
* Set **Autoscaling** to **Off**, and set **Number of instances** to **3**.
* Click **Create**.

In the side menu, go to **Network services > Load balancing**:
* Click **Create load balancer**
* Under **HTTP(S) Load Balancing**, click **Start configuration**.
* Select **From Internet to my VMs**, then click **Continue**.
* Enter `karaplan-classic-lb` as the load balancer **name**.
* In **Backend configuration**, click the dropdown menu to select **Backend services > Create a backend service**.
  * Enter `karaplan-classic-bes` as the backend service **name**.
  * Select `karaplan-classic-ig` as the **Instance group**, `8080` as the port number, then click **Done**.
  * In **Health check**, click **Create a health check** 
    * Enter `karaplan-hc` as the health check **name**.
    * Select **HTTP** as the **Protocol**, and `8080` as the port number.
    * Enter `/actuator/health` as the **Request path**.
  * Expand the configuration options at the bottom.
  * Select **Generated cookie** as the **Session affinity**.
  * Click **Create**.
* In **Frontend configuration**:
  * Enter `karaplan-classic-frontend` as the frontend service **name**.
  * In the **IP Address** dropdown, **Create IP address** named `karaplan-ip`.
  * If you *don't* have a custom domain name, leave **HTTP** as the **Protocol**.
  * If you *do* have a custom domain name:
    * Select **HTTPS** as the **Protocol**.
    * In the **Certificate** dropdown, **Create a new certificate** named `karaplan-ssl-cert` for your custom domain name.
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

    (TODO)
