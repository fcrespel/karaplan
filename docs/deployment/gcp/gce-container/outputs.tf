output "http_url_ip" {
  value       = "http://${google_compute_global_address.karaplan-ip.address}"
  description = "HTTP URL of the load balancer"
}
output "https_url_ip" {
  value       = "https://${google_compute_global_address.karaplan-ip.address}"
  description = "HTTPS URL of the load balancer"
}
output "http_url_domain" {
  value       = "http://${local.dns_name}"
  description = "HTTP URL of the custom domain"
}
output "https_url_domain" {
  value       = "https://${local.dns_name}"
  description = "HTTPS URL of the custom domain"
}
