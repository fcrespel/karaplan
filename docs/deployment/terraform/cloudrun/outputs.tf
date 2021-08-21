output "https_url_service" {
  value       = module.cloudrun.https_url_service
  description = "HTTPS URL of the service"
}
output "https_url_domain" {
  value       = module.cloudrun.https_url_domain
  description = "HTTPS URL of the custom domain"
}
