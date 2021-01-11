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
variable "node_count" {
  default     = 1
  description = "GKE node count per zone"
}
variable "machine_type" {
  default     = "n1-standard-2"
  description = "GKE node machine type"
}
