# Google Cloud SQL

This example uses [Cloud SQL](https://cloud.google.com/sql/) to deploy a MySQL database for persistence.

## Using Cloud Console

Go to [Cloud Console](https://console.cloud.google.com) and make sure the appropriate project is selected in the header menu.

In the side menu, go to **SQL**:
* Click **Create instance** and choose **MySQL**.
* Choose an **Instance ID** such as `karaplan`.
* Generate a **root password** or type a secure one.
* Choose a **Region** (e.g. `europe-west1`).
* Expand the configuration options at the bottom.
* In the **Connectivity** section, enable **Private IP** on the `default` network.
* Adjust **Backup** and **Maintenance** settings if necessary.
* Click **Create**.

When the database instance is ready:
* In the **Database** section, click **Create database**, enter name `karaplan`, select charset `utf8mb4` and collation `utf8mb4_general_ci`.
* In the **User** section, click **Create user account**, enter name `karaplan` and a secure password.

Take note of the **Private IP** and **user/password** for use during application deployment.

## Using Cloud Shell / SDK

Use the following commands in [Cloud Shell](https://cloud.google.com/shell/) or anywhere the [Cloud SDK](https://cloud.google.com/sdk/) is installed:

    # Set variables, adjust them as needed
    REGION=$(gcloud config get-value compute/region)
    ROOT_PASSWORD=$(</dev/urandom tr -dc A-Za-z0-9 | head -c16)
    USER_PASSWORD=$(</dev/urandom tr -dc A-Za-z0-9 | head -c16)

    # Create database instance (takes some time)
    gcloud beta sql instances create karaplan --database-version=MYSQL_5_7 --tier=db-n1-standard-1 --region=$REGION --network=default --root-password=$ROOT_PASSWORD

    # Create database
    gcloud sql databases create karaplan --instance=karaplan --charset=utf8mb4 --collation=utf8mb4_general_ci

    # Create user
    gcloud sql users create karaplan --instance=karaplan --host=% --password=$USER_PASSWORD
    echo "Created user karaplan / $USER_PASSWORD"

Take note of the **Private IP** and **user/password** for use during application deployment.

## Local debugging

To connect a local client for debugging, you may use **Cloud SQL Proxy**:

    PROJECT_ID=$(gcloud config get-value project)
    REGION=$(gcloud config get-value compute/region)

    cloud_sql_proxy -instances=$PROJECT_ID:$REGION:karaplan=tcp:3306

Then connect to localhost:3306 with the user created earlier.

## Using Terraform

You may use [Terraform](https://terraform.io) to provision all resources automatically. See the `main.tf` and `variables.tf` files for more information.

First create a `terraform.tfvars` file in this directory, providing appropriate values for all variables:

    credentials = "/path/to/credentials.json"
    project_id = "your-project-id"
    region = "europe-west1"
    db_password = "toComplete"

Then, run the following commands:

    terraform init
    terraform apply

Take note of the **Private IP** and **user/password** for use during application deployment.
