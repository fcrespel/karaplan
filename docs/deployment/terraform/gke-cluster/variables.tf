variable "name" {
  default     = "karaplan"
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
variable "network_name" {
  default     = "default"
  description = "GCP network to use"
}
variable "subnetwork_name" {
  default     = "default"
  description = "GCP subnetwork to use"
}
