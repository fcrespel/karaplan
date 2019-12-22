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

// Network
data "google_compute_network" "karaplan-network" {
  name = var.network
}

// Database private IP address
resource "google_compute_global_address" "karaplan-db-private-ip" {
  provider      = google-beta
  name          = "${var.name}-db-private-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = data.google_compute_network.karaplan-network.self_link
}

// Database private VPC connection
resource "google_service_networking_connection" "karaplan-db-private-vpc" {
  provider                = google-beta
  network                 = data.google_compute_network.karaplan-network.self_link
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.karaplan-db-private-ip.name]
}

// Database instance
resource "google_sql_database_instance" "karaplan-db-instance" {
  name             = "${var.name}-db-instance"
  database_version = "MYSQL_5_7"
  region           = var.region
  depends_on       = [google_service_networking_connection.karaplan-db-private-vpc]

  settings {
    tier = "db-${var.machine_type}"
    ip_configuration {
      ipv4_enabled    = false
      private_network = data.google_compute_network.karaplan-network.self_link
    }
    backup_configuration {
      enabled    = true
      start_time = "03:00"
    }
  }
}

// Database name
resource "google_sql_database" "karaplan-db" {
  name      = var.name
  instance  = google_sql_database_instance.karaplan-db-instance.name
  charset   = "utf8mb4"
  collation = "utf8mb4_general_ci"
}

// Database user
resource "google_sql_user" "karaplan-db-user" {
  name     = var.name
  instance = google_sql_database_instance.karaplan-db-instance.name
  host     = "%"
  password = var.db_password
}

// Outputs
output "db_private_address" {
  value       = google_sql_database_instance.karaplan-db-instance.private_ip_address
  description = "Database private IP address"
}
output "db_name" {
  value       = google_sql_database.karaplan-db.name
  description = "Database name"
}
output "db_user" {
  value       = google_sql_user.karaplan-db-user.name
  description = "Database user name"
}
output "db_password" {
  value       = google_sql_user.karaplan-db-user.password
  description = "Database user password"
}
