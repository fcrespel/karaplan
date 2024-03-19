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
variable "network" {
  default     = "default"
  description = "VPC network name"
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
variable "min_instances_count" {
  default     = 0
  description = "Minimum number of instances to create"
}
variable "max_instances_count" {
  default     = 5
  description = "Maximum number of instances to create"
}
