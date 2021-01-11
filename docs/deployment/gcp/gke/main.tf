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

// Environment secret
resource "kubernetes_secret" "karaplan-env-secret" {
  metadata {
    name      = "${var.name}-env-secret"
    namespace = var.namespace
  }
  data = {
    SPRING_DATASOURCE_USERNAME                                       = var.db_username
    SPRING_DATASOURCE_PASSWORD                                       = var.db_password
    SPRING_DATASOURCE_URL                                            = "jdbc:mysql:///${var.db_name}?useSSL=false&socketFactory=com.google.cloud.sql.mysql.SocketFactory&cloudSqlInstance=${var.db_instance}"
    SPRING_JPA_DATABASEPLATFORM                                      = "org.hibernate.dialect.MySQL5InnoDBDialect"
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID       = var.google_oauth_clientid
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET   = var.google_oauth_clientsecret
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTID     = var.facebook_oauth_clientid
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTSECRET = var.facebook_oauth_clientsecret
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID       = var.github_oauth_clientid
    SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET   = var.github_oauth_clientsecret
    SPRING_SESSION_STORETYPE                                         = "redis"
    SPRING_REDIS_HOST                                                = var.redis_host
  }
}

// Helm release
resource "helm_release" "karaplan-helm-release" {
  name      = var.name
  chart     = "${path.module}/../../helm/karaplan"
  namespace = var.namespace

  set {
    name  = "replicaCount"
    value = var.replica_count
  }
  set {
    name  = "ingress.enabled"
    value = var.http_enabled || var.https_enabled
  }
  set {
    name  = "ingress.annotations.kubernetes\\.io/ingress\\.allow-http"
    type  = "string"
    value = var.http_enabled
  }
  set {
    name  = "ingress.annotations.kubernetes\\.io/ingress\\.global-static-ip-name"
    type  = "string"
    value = google_compute_global_address.karaplan-ip.name
  }
  set {
    name  = "ingress.annotations.ingress\\.gcp\\.kubernetes\\.io/pre-shared-cert"
    type  = "string"
    value = var.https_enabled ? google_compute_managed_ssl_certificate.karaplan-ssl-cert[0].name : ""
  }
  set {
    name  = "backendConfig.enabled"
    value = true
  }
  set {
    name  = "application.enabled"
    value = var.application_enabled
  }
  set {
    name  = "resources.limits.cpu"
    value = "1000m"
  }
  set {
    name  = "resources.limits.memory"
    value = "1Gi"
  }
  set {
    name  = "resources.requests.cpu"
    value = "500m"
  }
  set {
    name  = "resources.requests.memory"
    value = "512Mi"
  }
  set {
    name  = "envFromSecret"
    value = kubernetes_secret.karaplan-env-secret.metadata[0].name
  }
}
