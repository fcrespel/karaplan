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

// Forwarding rule (HTTP)
resource "google_compute_global_forwarding_rule" "karaplan-fwd-http" {
  count                 = var.http_enabled ? 1 : 0
  name                  = "${var.name}-fwd-http"
  project               = var.project_id
  target                = google_compute_target_http_proxy.karaplan-http-proxy[0].self_link
  ip_address            = google_compute_global_address.karaplan-ip.address
  port_range            = "80"
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

// Forwarding rule (HTTPS)
resource "google_compute_global_forwarding_rule" "karaplan-fwd-https" {
  count                 = var.https_enabled ? 1 : 0
  name                  = "${var.name}-fwd-https"
  project               = var.project_id
  target                = google_compute_target_https_proxy.karaplan-https-proxy[0].self_link
  ip_address            = google_compute_global_address.karaplan-ip.address
  port_range            = "443"
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

// Target proxy (HTTP)
resource "google_compute_target_http_proxy" "karaplan-http-proxy" {
  count   = var.http_enabled ? 1 : 0
  name    = "${var.name}-http-proxy"
  project = var.project_id
  url_map = google_compute_url_map.karaplan-url-map.self_link
}

// Target proxy (HTTPS)
resource "google_compute_target_https_proxy" "karaplan-https-proxy" {
  count            = var.https_enabled ? 1 : 0
  name             = "${var.name}-https-proxy"
  project          = var.project_id
  url_map          = google_compute_url_map.karaplan-url-map.self_link
  ssl_certificates = [google_compute_managed_ssl_certificate.karaplan-ssl-cert[0].self_link]
}

// URL map
resource "google_compute_url_map" "karaplan-url-map" {
  name            = "${var.name}-url-map"
  project         = var.project_id
  default_service = google_compute_backend_service.karaplan-bes.self_link
}

// Backend service
resource "google_compute_backend_service" "karaplan-bes" {
  name      = "${var.name}-bes"
  project   = var.project_id
  port_name = "http"
  protocol  = "HTTP"
  backend {
    group = google_compute_region_instance_group_manager.karaplan-ig.instance_group
  }
  health_checks         = [google_compute_http_health_check.karaplan-hc.self_link]
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

// Health check
resource "google_compute_http_health_check" "karaplan-hc" {
  name         = "${var.name}-hc"
  project      = var.project_id
  port         = "8080"
  request_path = "/actuator/health/readiness"
}

// Instance group manager
resource "google_compute_region_instance_group_manager" "karaplan-ig" {
  name               = "${var.name}-ig"
  base_instance_name = var.name
  project            = var.project_id
  region             = var.region
  target_size        = var.instances_count

  version {
    instance_template = google_compute_instance_template.karaplan-template.self_link
  }

  update_policy {
    type                  = "PROACTIVE"
    minimal_action        = "RESTART"
    max_unavailable_fixed = 3
  }

  named_port {
    name = "http"
    port = "8080"
  }
}

// Instance template
resource "google_compute_instance_template" "karaplan-template" {
  name_prefix  = "${var.name}-template-"
  project      = var.project_id
  tags         = [var.name]
  machine_type = var.machine_type

  lifecycle {
    create_before_destroy = true
  }

  disk {
    source_image = data.google_compute_image.karaplan-image.self_link
    auto_delete  = true
    boot         = true
  }

  network_interface {
    network = "default"
    access_config {
      // Ephemeral IP
    }
  }

  metadata = {
    startup-script-url = "gs://${google_storage_bucket_object.karaplan-startup.bucket}/${google_storage_bucket_object.karaplan-startup.output_name}"
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}

// Startup script
resource "google_storage_bucket_object" "karaplan-startup" {
  name   = "${var.name}/karaplan-startup.sh"
  bucket = var.bucket
  content = templatefile("${path.module}/karaplan-startup.sh", {
    db_instance                 = var.db_instance
    db_name                     = var.db_name
    db_username                 = var.db_username
    db_password                 = var.db_password
    google_oauth_clientid       = var.google_oauth_clientid
    google_oauth_clientsecret   = var.google_oauth_clientsecret
    facebook_oauth_clientid     = var.facebook_oauth_clientid
    facebook_oauth_clientsecret = var.facebook_oauth_clientsecret
    github_oauth_clientid       = var.github_oauth_clientid
    github_oauth_clientsecret   = var.github_oauth_clientsecret
  })
}

// VM image
data "google_compute_image" "karaplan-image" {
  family  = "debian-12"
  project = "debian-cloud"
}
