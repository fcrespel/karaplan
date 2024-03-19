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

// Cloud Run service
resource "google_cloud_run_service" "karaplan-service" {
  name     = "${var.name}-service"
  project  = var.project_id
  location = var.region

  metadata {
    annotations = {
      "run.googleapis.com/ingress" = "all"
    }
  }
  template {
    metadata {
      annotations = {
        "autoscaling.knative.dev/minScale"     = var.min_instances_count
        "autoscaling.knative.dev/maxScale"     = var.max_instances_count
        "run.googleapis.com/client-name"       = "terraform"
        "run.googleapis.com/startup-cpu-boost" = "true"
      }
    }
    spec {
      service_account_name = google_service_account.karaplan-sa.email
      containers {
        image = "${var.region}-docker.pkg.dev/${var.project_id}/docker/karaplan:master"
        resources {
          limits = {
            cpu    = "1000m"
            memory = "1024Mi"
          }
        }
        env {
          name  = "SPRING_PROFILES_ACTIVE"
          value = "gcp"
        }
        env {
          name  = "SECRET_PREFIX"
          value = var.name
        }
      }
    }
  }
  autogenerate_revision_name = true
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

// Public access
resource "google_cloud_run_service_iam_member" "karaplan-service-iam-member" {
  service  = google_cloud_run_service.karaplan-service.name
  project  = var.project_id
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}

// Domain name mapping
resource "google_cloud_run_domain_mapping" "karaplan-service-mapping" {
  count    = var.dns_zone != "" ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = replace(google_dns_record_set.karaplan-dns-record[0].name, "/\\.$/", "")

  metadata {
    namespace = var.project_id
  }
  spec {
    route_name = google_cloud_run_service.karaplan-service.name
  }
}
