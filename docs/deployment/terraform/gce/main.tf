// Google Cloud provider
provider "google" {
  credentials = var.credentials
  project     = var.project_id
  region      = var.region
}

// Cloud SQL module
module "sql" {
  source     = "../../gcp/sql"
  name       = var.name
  project_id = var.project_id
  region     = var.region
}

// Secret Manager module
module "secret-manager" {
  source                      = "../../gcp/secret-manager"
  name                        = var.name
  project_id                  = var.project_id
  region                      = var.region
  db_instance                 = module.sql.db_instance
  db_name                     = module.sql.db_name
  db_username                 = module.sql.db_username
  db_password                 = module.sql.db_password
  google_oauth_clientid       = var.google_oauth_clientid
  google_oauth_clientsecret   = var.google_oauth_clientsecret
  github_oauth_clientid       = var.github_oauth_clientid
  github_oauth_clientsecret   = var.github_oauth_clientsecret
}

// Compute Engine module
module "gce" {
  source          = "../../gcp/gce"
  name            = var.name
  project_id      = var.project_id
  region          = var.region
  bucket          = var.project_id
  dns_project_id  = var.dns_project_id != "" ? var.dns_project_id : var.project_id
  dns_zone        = var.dns_zone
  dns_name_prefix = var.name
  http_enabled    = var.http_enabled
  https_enabled   = var.https_enabled
  instances_count = var.instances_count
  machine_type    = var.machine_type

  depends_on = [module.secret-manager]
}
