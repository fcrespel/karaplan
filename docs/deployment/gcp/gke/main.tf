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

// GKE cluster
resource "google_container_cluster" "karaplan-cluster" {
  name     = "${var.name}-cluster"
  location = var.region

  remove_default_node_pool = true
  initial_node_count       = 1

  master_auth {
    username = ""
    password = ""

    client_certificate_config {
      issue_client_certificate = false
    }
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
