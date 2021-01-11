// Network
data "google_compute_network" "karaplan-network" {
  name    = var.network
  project = var.project_id
}

// Redis instance
resource "google_redis_instance" "karaplan-redis" {
  name               = "${var.name}-redis"
  project            = var.project_id
  region             = var.region
  memory_size_gb     = 1
  authorized_network = data.google_compute_network.karaplan-network.self_link
}
