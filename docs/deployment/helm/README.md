# Helm chart

This directory contains a [Helm](https://helm.sh) chart that can be used to deploy the application to a Kubernetes cluster.

This guide assumes you already have a valid connection to a Kubernetes cluster, i.e. you can run `kubectl` commands. Setting up the Kubernetes cluster and client is out of scope of this documentation.

If you wish to deploy the application to a Google Kubernetes Engine (GKE) cluster, please see the dedicated [GKE](../gcp/gke) deployment instructions instead.

Otherwise, download and install the **Helm client** from the official [releases](https://github.com/helm/helm/releases) page.

Then, examine the **variables** available in the [values.yaml](karaplan/values.yaml) file and override them in your own local file, e.g. `karaplan.yaml` :

    ingress:
      enabled: true
    env:
      SPRING_DATASOURCE_USERNAME: "karaplan"
      SPRING_DATASOURCE_PASSWORD: "toComplete"
      SPRING_DATASOURCE_URL: "jdbc:mysql:///karaplan?useSSL=false&socketFactory=com.google.cloud.sql.mysql.SocketFactory&cloudSqlInstance=toComplete"
      SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID: "toComplete"
      SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET: "toComplete"
      SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID: "toComplete"
      SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET: "toComplete"

Run the following commands in this directory to deploy the application:

    # Preview template before installing it
    helm template karaplan ./karaplan -f karaplan.yaml

    # Install application
    helm upgrade -i karaplan ./karaplan -f karaplan.yaml

After several minutes, the application should become available at the configured ingress.
