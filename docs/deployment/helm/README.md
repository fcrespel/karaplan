# Helm chart

This directory contains a [Helm](https://helm.sh) chart that can be used to deploy the application to a Kubernetes cluster.

This guide assumes you already have a valid connection to a Kubernetes cluster, i.e. you can run `kubectl` commands. Setting up the Kubernetes cluster and client is out of scope of this documentation.

If you wish to deploy the application to a Google Kubernetes Engine (GKE) cluster, please see the dedicated [GKE](../gcp/gke) deployment instructions instead.

Otherwise, download and install the **Helm 2.x client** from the official [releases](https://github.com/helm/helm/releases) page.

Then, examine the **variables** available in the [values.yaml](karaplan/values.yaml) file and override them in your own local file, e.g. `karaplan.yaml` :

    datasource:
      url: jdbc:mysql://host:port/karaplan?useSSL=false
    secrets:
      datasource:
        username: karaplan
        password: toComplete
      google:
        clientId: toComplete
        clientSecret: toComplete
      facebook:
        clientId: toComplete
        clientSecret: toComplete
      github:
        clientId: toComplete
        clientSecret: toComplete
    ingress:
      enabled: true

Run the following commands in this directory to deploy the application:

    # Init Helm client and server
    helm init

    # Preview template before installing it
    helm template -f karaplan.yaml -n karaplan ./karaplan

    # Install application
    helm install -f karaplan.yaml -n karaplan ./karaplan

After several minutes, the application should become available at the configured ingress.
