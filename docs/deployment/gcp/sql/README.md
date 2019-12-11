# Google Cloud SQL

This example uses [Cloud SQL](https://cloud.google.com/sql/) to deploy a MySQL database for persistence.

## Using Cloud Console

(TODO)

## Using Cloud Shell / SDK

    # Set variables, adjust them as needed
    REGION=$(gcloud config get-value compute/region)
    ROOT_PASSWORD=$(</dev/urandom tr -dc A-Za-z0-9 | head -c16)
    USER_PASSWORD=$(</dev/urandom tr -dc A-Za-z0-9 | head -c16)

    # Create database instance (takes some time)
    gcloud beta sql instances create karaplan --database-version=MYSQL_5_7 --tier=db-n1-standard-1 --region=$REGION --network=default --root-password=$ROOT_PASSWORD --no-backup

    # Create database
    gcloud sql databases create karaplan --instance=karaplan --charset=utf8mb4 --collation=utf8mb4_general_ci

    # Create user
    gcloud sql users create karaplan --instance=karaplan --host=% --password=$USER_PASSWORD
    echo "Created user karaplan / $USER_PASSWORD"

To connect a local client for debugging, you may use Cloud SQL Proxy:

    PROJECT_ID=$(gcloud config get-value project)
    REGION=$(gcloud config get-value compute/region)

    cloud_sql_proxy -instances=$PROJECT_ID:$REGION:karaplan=tcp:3306

Then connect to localhost:3306 with the user created earlier.
