variable "name" {
  default     = "karaplan"
  description = "Name to use in all resources of this module"
}
variable "project_id" {
  description = "GCP project ID"
}
variable "region" {
  description = "GCP region"
}
variable "dns_project_id" {
  default     = ""
  description = "Cloud DNS project ID"
}
variable "dns_zone" {
  default     = ""
  description = "Cloud DNS zone name"
}
variable "dns_name_prefix" {
  default     = "karaplan"
  description = "DNS name prefix"
}
variable "http_enabled" {
  default     = true
  description = "Enable HTTP load balancing"
}
variable "https_enabled" {
  default     = false
  description = "Enable HTTPS load balancing"
}
variable "namespace" {
  default     = "default"
  description = "Kubernetes namespace"
}
variable "replica_count" {
  default     = 3
  description = "Deployment replica count"
}
