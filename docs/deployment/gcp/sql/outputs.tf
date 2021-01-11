output "db_instance" {
  value       = google_sql_database_instance.karaplan-db-instance.connection_name
  description = "Database instance (project_id:region:instance_name)"
}
output "db_name" {
  value       = google_sql_database.karaplan-db.name
  description = "Database name"
}
output "db_username" {
  value       = google_sql_user.karaplan-db-user.name
  description = "Database user name"
}
output "db_password" {
  value       = random_password.karaplan-db-password.result
  description = "Database user password"
  sensitive   = true
}
