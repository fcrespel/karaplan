// Local variables
locals {
  dns_name = var.dns_zone != "" ? replace(google_dns_record_set.karaplan-dns-record[0].name, "/\\.$/", "") : "${replace(google_compute_global_address.karaplan-ip.address, ".", "-")}.sslip.io"
}

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
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.karaplan-ip.address]
}

// Global IP
resource "google_compute_global_address" "karaplan-ip" {
  name         = "${var.name}-ip"
  project      = var.project_id
  address_type = "EXTERNAL"
}

// SSL certificate
resource "google_compute_managed_ssl_certificate" "karaplan-ssl-cert" {
  count   = var.https_enabled ? 1 : 0
  name    = "${var.name}-ssl-cert"
  project = var.project_id
  managed {
    domains = [local.dns_name]
  }
}

// Service account
resource "google_service_account" "karaplan-sa" {
  project    = var.project_id
  account_id = var.name
}
resource "google_service_account_iam_member" "karaplan-sa-workload-identity" {
  service_account_id = google_service_account.karaplan-sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${var.name}]"
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

// Helm release
resource "helm_release" "karaplan-helm-release" {
  name      = var.name
  chart     = "${path.module}/../../helm/karaplan"
  namespace = var.namespace

  values = [templatefile("${path.module}/values.yaml", {
    replica_count       = var.replica_count
    gcp_service_account = google_service_account.karaplan-sa.email
    gcp_ip_address      = google_compute_global_address.karaplan-ip.name
    gcp_ssl_cert        = var.https_enabled ? google_compute_managed_ssl_certificate.karaplan-ssl-cert[0].name : ""
    ingress_enabled     = var.http_enabled || var.https_enabled
    ingress_allow_http  = var.http_enabled
    secret_prefix       = var.name
  })]
}
