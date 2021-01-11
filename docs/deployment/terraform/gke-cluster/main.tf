// Google Cloud provider
provider "google" {
  credentials = var.credentials
  project     = var.project_id
  region      = var.region
}

// GKE custom network
resource "google_compute_network" "karaplan-network" {
  name                    = "${var.name}-network"
  project                 = var.project_id
  auto_create_subnetworks = false
}

// GKE subnetwork with alias IP for pods and services
resource "google_compute_subnetwork" "karaplan-subnet" {
  name          = "${var.name}-subnet"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.karaplan-network.self_link
  ip_cidr_range = "10.132.0.0/20"

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
  project    = var.project_id
  location   = var.region
  network    = google_compute_network.karaplan-network.self_link
  subnetwork = google_compute_subnetwork.karaplan-subnet.self_link

  remove_default_node_pool = true
  initial_node_count       = 1

  release_channel {
    channel = "REGULAR"
  }

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
  project    = var.project_id
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
