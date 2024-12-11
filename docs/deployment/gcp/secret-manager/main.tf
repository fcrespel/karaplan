// Local variables
locals {
  secrets = {
    "${var.name}-db-instance"            = var.db_instance
    "${var.name}-db-name"                = var.db_name
    "${var.name}-db-username"            = var.db_username
    "${var.name}-db-password"            = var.db_password
    "${var.name}-google-client-id"       = var.google_oauth_clientid
    "${var.name}-google-client-secret"   = var.google_oauth_clientsecret
    "${var.name}-github-client-id"       = var.github_oauth_clientid
    "${var.name}-github-client-secret"   = var.github_oauth_clientsecret
  }
}

// Secret
resource "google_secret_manager_secret" "secret" {
  for_each  = local.secrets
  secret_id = each.key
  project   = var.project_id

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

// Secret version
resource "google_secret_manager_secret_version" "secret" {
  for_each    = local.secrets
  secret      = google_secret_manager_secret.secret[each.key].id
  secret_data = each.value
}
