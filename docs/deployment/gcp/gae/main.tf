// DNS zone
data "google_dns_managed_zone" "karaplan-dns-zone" {
  count   = var.dns_zone != "" ? 1 : 0
  name    = var.dns_zone
  project = var.dns_project_id
}

// DNS record
resource "google_dns_record_set" "karaplan-dns-record" {
  count        = var.dns_zone != "" ? 1 : 0
  name         = "${var.dns_name_prefix}.${data.google_dns_managed_zone.karaplan-dns-zone[0].dns_name}"
  project      = data.google_dns_managed_zone.karaplan-dns-zone[0].project
  managed_zone = data.google_dns_managed_zone.karaplan-dns-zone[0].name
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["ghs.googlehosted.com."]
}

// Domain name mapping
resource "google_app_engine_domain_mapping" "karaplan-domain-mapping" {
  count       = var.dns_zone != "" ? 1 : 0
  project     = var.project_id
  domain_name = replace(google_dns_record_set.karaplan-dns-record[0].name, "/\\.$/", "")

  ssl_settings {
    ssl_management_type = "AUTOMATIC"
  }
}

// Service account
resource "google_service_account" "karaplan-sa" {
  project    = var.project_id
  account_id = var.name
}
resource "google_project_iam_member" "karaplan-sa-secret-accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.karaplan-sa.email}"
}
resource "google_project_iam_member" "karaplan-sa-sql-client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.karaplan-sa.email}"
}
