// Google Cloud provider
provider google {
  credentials = var.credentials
  project     = var.project_id
  region      = var.region
  version     = "~> 3.0"
}
provider google-beta {
  credentials = var.credentials
  project     = var.project_id
  region      = var.region
  version     = "~> 3.0"
}

// Global IP
resource "google_compute_global_address" "karaplan-ip" {
  name         = "${var.name}-ip"
  address_type = "EXTERNAL"
}

// SSL certificate
resource "google_compute_managed_ssl_certificate" "karaplan-ssl-cert" {
  count    = var.https_enabled ? 1 : 0
  provider = google-beta
  name     = "${var.name}-ssl-cert"
  managed {
    domains = [var.domain_name]
  }
}

// Forwarding rule (HTTP)
resource "google_compute_global_forwarding_rule" "karaplan-fwd-http" {
  count      = var.http_enabled ? 1 : 0
  name       = "${var.name}-fwd-http"
  target     = google_compute_target_http_proxy.karaplan-http-proxy[0].self_link
  ip_address = google_compute_global_address.karaplan-ip.address
  port_range = "80"
}

// Forwarding rule (HTTPS)
resource "google_compute_global_forwarding_rule" "karaplan-fwd-https" {
  count      = var.https_enabled ? 1 : 0
  name       = "${var.name}-fwd-https"
  target     = google_compute_target_https_proxy.karaplan-https-proxy[0].self_link
  ip_address = google_compute_global_address.karaplan-ip.address
  port_range = "443"
}

// Target proxy (HTTP)
resource "google_compute_target_http_proxy" "karaplan-http-proxy" {
  count   = var.http_enabled ? 1 : 0
  name    = "${var.name}-http-proxy"
  url_map = google_compute_url_map.karaplan-url-map.self_link
}

// Target proxy (HTTPS)
resource "google_compute_target_https_proxy" "karaplan-https-proxy" {
  count            = var.https_enabled ? 1 : 0
  name             = "${var.name}-https-proxy"
  url_map          = google_compute_url_map.karaplan-url-map.self_link
  ssl_certificates = [google_compute_managed_ssl_certificate.karaplan-ssl-cert[0].self_link]
}

// URL map
resource "google_compute_url_map" "karaplan-url-map" {
  name            = "${var.name}-url-map"
  default_service = google_compute_backend_service.karaplan-bes.self_link
}

// Backend service
resource "google_compute_backend_service" "karaplan-bes" {
  name                    = "${var.name}-bes"
  port_name               = "http"
  protocol                = "HTTP"
  session_affinity        = "GENERATED_COOKIE"
  affinity_cookie_ttl_sec = 0
  backend {
    group = google_compute_region_instance_group_manager.karaplan-ig.instance_group
  }
  health_checks = [google_compute_http_health_check.karaplan-hc.self_link]
}

// Health check
resource "google_compute_http_health_check" "karaplan-hc" {
  name                = "${var.name}-hc"
  port                = "8080"
  request_path        = "/actuator/health"
}

// Instance group manager
resource "google_compute_region_instance_group_manager" "karaplan-ig" {
  name                      = "${var.name}-ig"
  base_instance_name        = var.name
  region                    = var.region
  distribution_policy_zones = var.zones
  target_size               = var.instances_count

  version {
    instance_template = google_compute_instance_template.karaplan-template.self_link
  }

  named_port {
    name = "http"
    port = "8080"
  }
}

// Instance template
resource "google_compute_instance_template" "karaplan-template" {
  name_prefix    = "${var.name}-template-"
  tags           = [var.name]
  machine_type   = var.machine_type

  lifecycle {
    create_before_destroy = true
  }

  disk {
    source_image = module.karaplan-container.source_image
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
    (module.karaplan-container.metadata_key) = module.karaplan-container.metadata_value
  }

  labels = {
    (module.karaplan-container.vm_container_label_key) = module.karaplan-container.vm_container_label
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}

module "karaplan-container" {
  source = "terraform-google-modules/container-vm/google"
  version = "2.0.0"

  container = {
    image = var.container_image
    env = [
      {
        name = "SPRING_DATASOURCE_USERNAME"
        value = var.db_username
      },
      {
        name = "SPRING_DATASOURCE_PASSWORD"
        value = var.db_password
      },
      {
        name = "SPRING_DATASOURCE_URL"
        value = "jdbc:mysql://${var.db_address}/${var.db_name}?useSSL=false"
      },
      {
        name = "SPRING_JPA_DATABASEPLATFORM"
        value = "org.hibernate.dialect.MySQL5InnoDBDialect"
      },
      {
        name = "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID"
        value = var.google_oauth_clientid
      },
      {
        name = "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET"
        value = var.google_oauth_clientsecret
      },
      {
        name = "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTID"
        value = var.facebook_oauth_clientid
      },
      {
        name = "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTSECRET"
        value = var.facebook_oauth_clientsecret
      },
      {
        name = "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID"
        value = var.github_oauth_clientid
      },
      {
        name = "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET"
        value = var.github_oauth_clientsecret
      }
    ]
  }

  restart_policy = "Always"
}

// Outputs
output "http_url_ip" {
  value = "http://${google_compute_global_address.karaplan-ip.address}"
  description = "HTTP URL of the load balancer"
}
output "https_url_ip" {
  value = "https://${google_compute_global_address.karaplan-ip.address}"
  description = "HTTPS URL of the load balancer"
}
output "http_url_domain" {
  value = "http://${var.domain_name}"
  description = "HTTP URL of the custom domain"
}
output "https_url_domain" {
  value = "https://${var.domain_name}"
  description = "HTTPS URL of the custom domain"
}
