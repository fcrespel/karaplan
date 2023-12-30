// Google Cloud provider
provider "google" {
  credentials = var.credentials
  project     = var.project_id
  region      = var.region
}

// GKE cluster
resource "google_container_cluster" "karaplan-cluster" {
  name                = "${var.name}-cluster"
  project             = var.project_id
  location            = var.region
  network             = var.network_name
  subnetwork          = var.subnetwork_name
  enable_autopilot    = true
  deletion_protection = false
}
