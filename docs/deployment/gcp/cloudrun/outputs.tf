output "https_url_service" {
  value       = google_cloud_run_service.karaplan-service.status[0].url
  description = "HTTPS URL of the service"
}
output "https_url_domain" {
  value       = var.dns_zone != "" ? "https://${replace(google_dns_record_set.karaplan-dns-record[0].name, "/\\.$/", "")}" : ""
  description = "HTTPS URL of the custom domain"
}
