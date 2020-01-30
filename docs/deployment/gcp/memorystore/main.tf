// Google Cloud provider
provider google {
  credentials = var.credentials
  project     = var.project_id
  region      = var.region
  version     = "~> 3.0"
}

// Network
data "google_compute_network" "karaplan-network" {
  name = var.network
}

// Redis instance
resource "google_redis_instance" "karaplan-redis" {
  name               = "${var.name}-redis"
  region             = var.region
  memory_size_gb     = 1
  authorized_network = data.google_compute_network.karaplan-network.self_link
}

// Outputs
output "redis_host" {
  value       = google_redis_instance.karaplan-redis.host
  description = "Redis host"
}
output "redis_port" {
  value       = google_redis_instance.karaplan-redis.port
  description = "Redis port"
}
