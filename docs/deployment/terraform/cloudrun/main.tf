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

// Cloud Run service
module "cloudrun" {
  source          = "../../gcp/cloudrun"
  name            = var.name
  project_id      = var.project_id
  region          = var.region
  dns_project_id  = var.dns_project_id != "" ? var.dns_project_id : var.project_id
  dns_zone        = var.dns_zone
  dns_name_prefix = var.name

  depends_on = [module.secret-manager]
}
