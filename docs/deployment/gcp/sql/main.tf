// Database instance
resource "google_sql_database_instance" "karaplan-db-instance" {
  name                = "${var.name}-db-instance"
  project             = var.project_id
  region              = var.region
  database_version    = "MYSQL_8_0"
  deletion_protection = false

  settings {
    tier = "db-${var.machine_type}"
    ip_configuration {
      ipv4_enabled = true
    }
    backup_configuration {
      enabled    = true
      start_time = "03:00"
    }
    maintenance_window {
      day  = 7
      hour = 11
    }
  }
}

// Database name
resource "google_sql_database" "karaplan-db" {
  name      = var.name
  project   = var.project_id
  instance  = google_sql_database_instance.karaplan-db-instance.name
  charset   = "utf8mb4"
  collation = "utf8mb4_general_ci"
}

// Database user
resource "google_sql_user" "karaplan-db-user" {
  name     = var.name
  project  = var.project_id
  instance = google_sql_database_instance.karaplan-db-instance.name
  host     = "%"
  password = random_password.karaplan-db-password.result
}

// Database password
resource "random_password" "karaplan-db-password" {
  length = 16
}
