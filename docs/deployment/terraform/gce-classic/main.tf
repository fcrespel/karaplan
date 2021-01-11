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

// Cloud Memorystore module
module "memorystore" {
  source     = "../../gcp/memorystore"
  name       = var.name
  project_id = var.project_id
  region     = var.region
}

// Compute Engine "classic" module
module "gce-classic" {
  source                      = "../../gcp/gce-classic"
  name                        = var.name
  project_id                  = var.project_id
  region                      = var.region
  bucket                      = var.project_id
  dns_project_id              = var.dns_project_id != "" ? var.dns_project_id : var.project_id
  dns_zone                    = var.dns_zone
  dns_name_prefix             = var.name
  http_enabled                = var.http_enabled
  https_enabled               = var.https_enabled
  instances_count             = var.instances_count
  machine_type                = var.machine_type
  db_instance                 = module.sql.db_instance
  db_name                     = module.sql.db_name
  db_username                 = module.sql.db_username
  db_password                 = module.sql.db_password
  redis_host                  = module.memorystore.redis_host
  google_oauth_clientid       = var.google_oauth_clientid
  google_oauth_clientsecret   = var.google_oauth_clientsecret
  facebook_oauth_clientid     = var.facebook_oauth_clientid
  facebook_oauth_clientsecret = var.facebook_oauth_clientsecret
  github_oauth_clientid       = var.github_oauth_clientid
  github_oauth_clientsecret   = var.github_oauth_clientsecret
}
