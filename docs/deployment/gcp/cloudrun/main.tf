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
        "autoscaling.knative.dev/minScale" = var.min_instances_count
        "autoscaling.knative.dev/maxScale" = var.max_instances_count
        "run.googleapis.com/client-name"   = "terraform"
      }
    }
    spec {
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
          name  = "SPRING_DATASOURCE_USERNAME"
          value = var.db_username
        }
        env {
          name  = "SPRING_DATASOURCE_PASSWORD"
          value = var.db_password
        }
        env {
          name  = "SPRING_DATASOURCE_URL"
          value = "jdbc:mysql:///${var.db_name}?useSSL=false&socketFactory=com.google.cloud.sql.mysql.SocketFactory&cloudSqlInstance=${var.db_instance}"
        }
        env {
          name  = "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID"
          value = var.google_oauth_clientid
        }
        env {
          name  = "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET"
          value = var.google_oauth_clientsecret
        }
        env {
          name  = "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTID"
          value = var.facebook_oauth_clientid
        }
        env {
          name  = "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTSECRET"
          value = var.facebook_oauth_clientsecret
        }
        env {
          name  = "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID"
          value = var.github_oauth_clientid
        }
        env {
          name  = "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET"
          value = var.github_oauth_clientsecret
        }
      }
    }
  }
  autogenerate_revision_name = true
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
