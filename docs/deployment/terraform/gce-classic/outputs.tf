output "http_url_ip" {
  value       = module.gce-classic.http_url_ip
  description = "HTTP URL of the load balancer"
}
output "https_url_ip" {
  value       = module.gce-classic.https_url_ip
  description = "HTTPS URL of the load balancer"
}
output "http_url_domain" {
  value       = module.gce-classic.http_url_domain
  description = "HTTP URL of the custom domain"
}
output "https_url_domain" {
  value       = module.gce-classic.https_url_domain
  description = "HTTPS URL of the custom domain"
}
