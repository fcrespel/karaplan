// Google Cloud provider
provider "google" {
  credentials = var.credentials
  project     = var.project_id
  region      = var.region
}

// Google Cloud client config
data "google_client_config" "default" {
}

// GKE cluster
data "google_container_cluster" "karaplan-cluster" {
  name     = var.gke_cluster_name
  project  = var.project_id
  location = var.region
}

// Kubernetes provider
provider "kubernetes" {
  host                   = "https://${data.google_container_cluster.karaplan-cluster.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(data.google_container_cluster.karaplan-cluster.master_auth[0].cluster_ca_certificate)
}

// Helm provider
provider "helm" {
  kubernetes {
    host                   = "https://${data.google_container_cluster.karaplan-cluster.endpoint}"
    token                  = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(data.google_container_cluster.karaplan-cluster.master_auth[0].cluster_ca_certificate)
  }
}

// Cloud SQL module
module "sql" {
  source     = "../../gcp/sql"
  name       = var.name
  project_id = var.project_id
  region     = var.region
}

// GKE module
module "gke" {
  source                      = "../../gcp/gke"
  name                        = var.name
  project_id                  = var.project_id
  region                      = var.region
  dns_project_id              = var.dns_project_id != "" ? var.dns_project_id : var.project_id
  dns_zone                    = var.dns_zone
  dns_name_prefix             = var.name
  http_enabled                = var.http_enabled
  https_enabled               = var.https_enabled
  namespace                   = var.gke_namespace
  replica_count               = var.replica_count
  db_instance                 = module.sql.db_instance
  db_name                     = module.sql.db_name
  db_username                 = module.sql.db_username
  db_password                 = module.sql.db_password
  google_oauth_clientid       = var.google_oauth_clientid
  google_oauth_clientsecret   = var.google_oauth_clientsecret
  facebook_oauth_clientid     = var.facebook_oauth_clientid
  facebook_oauth_clientsecret = var.facebook_oauth_clientsecret
  github_oauth_clientid       = var.github_oauth_clientid
  github_oauth_clientsecret   = var.github_oauth_clientsecret
}
