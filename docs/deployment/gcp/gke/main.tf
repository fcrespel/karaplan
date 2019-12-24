// Google Cloud provider
provider google {
  credentials = var.credentials
  project     = var.project_id
  region      = var.region
  version     = "~> 3.0"
}
provider google-beta {
  credentials = var.credentials
  project     = var.project_id
  region      = var.region
  version     = "~> 3.0"
}

// Google Cloud client config
data "google_client_config" "default" {
}

// Global IP
resource "google_compute_global_address" "karaplan-ip" {
  name         = "${var.name}-ip"
  address_type = "EXTERNAL"
}

// SSL certificate
resource "google_compute_managed_ssl_certificate" "karaplan-ssl-cert" {
  count    = var.https_enabled ? 1 : 0
  provider = google-beta
  name     = "${var.name}-ssl-cert"
  managed {
    domains = [var.domain_name]
  }
}

// GKE custom network
resource "google_compute_network" "karaplan-network" {
  name                    = "${var.name}-network"
  auto_create_subnetworks = false
}

// GKE subnetwork with alias IP for pods and services
resource "google_compute_subnetwork" "karaplan-subnet" {
  name                     = "${var.name}-subnet"
  region                   = var.region
  network                  = google_compute_network.karaplan-network.self_link
  ip_cidr_range            = "10.132.0.0/20"

  secondary_ip_range {
    range_name    = "${var.name}-pods"
    ip_cidr_range = "10.24.0.0/14"
  }
  secondary_ip_range {
    range_name    = "${var.name}-services"
    ip_cidr_range = "10.28.0.0/20"
  }
}

// GKE cluster
resource "google_container_cluster" "karaplan-cluster" {
  name       = "${var.name}-cluster"
  location   = var.region
  network    = google_compute_network.karaplan-network.self_link
  subnetwork = google_compute_subnetwork.karaplan-subnet.self_link

  remove_default_node_pool = true
  initial_node_count       = 1

  master_auth {
    username = ""
    password = ""

    client_certificate_config {
      issue_client_certificate = false
    }
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = "${var.name}-pods"
    services_secondary_range_name = "${var.name}-services"
  }
}

// GKE node pool
resource "google_container_node_pool" "karaplan-node-pool" {
  name       = "${var.name}-node-pool"
  location   = var.region
  cluster    = google_container_cluster.karaplan-cluster.name
  node_count = var.node_count

  node_config {
    machine_type = var.machine_type

    metadata = {
      disable-legacy-endpoints = "true"
    }

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}

// Kubernetes provider
provider "kubernetes" {
  load_config_file       = false
  host                   = "https://${google_container_cluster.karaplan-cluster.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.karaplan-cluster.master_auth[0].cluster_ca_certificate)
  version                = "~> 1.10"
}

// Helm service account
resource "kubernetes_service_account" "helm-sa" {
  metadata {
    name = "helm"
    namespace = "kube-system"
  }
}
resource "kubernetes_cluster_role_binding" "helm-sa-binding" {
  metadata {
    name = "helm"
  }
  role_ref {
    api_group= "rbac.authorization.k8s.io"
    kind = "ClusterRole"
    name = "cluster-admin"
  }
  subject {
    kind = "ServiceAccount"
    name = kubernetes_service_account.helm-sa.metadata[0].name
    namespace = kubernetes_service_account.helm-sa.metadata[0].namespace
  }
}

// Helm provider
provider "helm" {
  service_account = kubernetes_service_account.helm-sa.metadata[0].name
  kubernetes {
    load_config_file       = false
    host                   = "https://${google_container_cluster.karaplan-cluster.endpoint}"
    token                  = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(google_container_cluster.karaplan-cluster.master_auth[0].cluster_ca_certificate)
  }
  version = "~> 0.10"
}

// Helm release
resource "helm_release" "karaplan-helm-release" {
  name  = var.name
  chart = "${path.module}/../../helm/karaplan"

  set {
    name  = "replicaCount"
    value = var.replica_count
  }
  set {
    name  = "ingress.enabled"
    value = var.http_enabled || var.https_enabled
  }
  set_string {
    name  = "ingress.annotations.kubernetes\\.io/ingress\\.allow-http"
    value = var.http_enabled
  }
  set_string {
    name  = "ingress.annotations.kubernetes\\.io/ingress\\.global-static-ip-name"
    value = google_compute_global_address.karaplan-ip.name
  }
  set_string {
    name  = "ingress.annotations.ingress\\.gcp\\.kubernetes\\.io/pre-shared-cert"
    value = var.https_enabled ? google_compute_managed_ssl_certificate.karaplan-ssl-cert[0].name : ""
  }
  set {
    name  = "backendConfig.enabled"
    value = true
  }
  set {
    name  = "application.enabled"
    value = var.application_enabled
  }
  set {
    name  = "resources.limits.cpu"
    value  = "1000m"
  }
  set {
    name  = "resources.limits.memory"
    value  = "1Gi"
  }
  set {
    name  = "resources.requests.cpu"
    value  = "500m"
  }
  set {
    name  = "resources.requests.memory"
    value  = "512Mi"
  }
  set {
    name  = "datasource.url"
    value = "jdbc:mysql:///${var.db_name}?useSSL=false&socketFactory=com.google.cloud.sql.mysql.SocketFactory&cloudSqlInstance=${var.db_instance}"
  }
  set {
    name  = "secrets.datasource.username"
    value = var.db_username
  }
  set_sensitive {
    name  = "secrets.datasource.password"
    value = var.db_password
  }
  set {
    name  = "secrets.google.clientId"
    value = var.google_oauth_clientid
  }
  set_sensitive {
    name  = "secrets.google.clientSecret"
    value = var.google_oauth_clientsecret
  }
  set {
    name  = "secrets.facebook.clientId"
    value = var.facebook_oauth_clientid
  }
  set_sensitive {
    name  = "secrets.facebook.clientSecret"
    value = var.facebook_oauth_clientsecret
  }
  set {
    name  = "secrets.github.clientId"
    value = var.github_oauth_clientid
  }
  set_sensitive {
    name  = "secrets.github.clientSecret"
    value = var.github_oauth_clientsecret
  }
}

// Outputs
output "http_url_ip" {
  value = "http://${google_compute_global_address.karaplan-ip.address}"
  description = "HTTP URL of the load balancer"
}
output "https_url_ip" {
  value = "https://${google_compute_global_address.karaplan-ip.address}"
  description = "HTTPS URL of the load balancer"
}
output "http_url_domain" {
  value = "http://${var.domain_name}"
  description = "HTTP URL of the custom domain"
}
output "https_url_domain" {
  value = "https://${var.domain_name}"
  description = "HTTPS URL of the custom domain"
}
