variable "name" {
  default = "karaplan-gke"
  description = "Name to use in all resources of this module"
}
variable "credentials" {
  description = "Service account credentials JSON file"
}
variable "project_id" {
  description = "GCP project ID"
}
variable "region" {
  description = "GCP region"
}
variable "domain_name" {
  default = "your.custom.domain"
  description = "Domain name"
}
variable "http_enabled" {
  default = true
  description = "Enable HTTP load balancing"
}
variable "https_enabled" {
  default = false
  description = "Enable HTTPS load balancing"
}
variable "node_count" {
  default = 1
  description = "GKE node count per zone"
}
variable "machine_type" {
  default = "n1-standard-2"
  description = "GKE node machine type"
}
