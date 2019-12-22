variable "name" {
  default = "karaplan"
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
variable "network" {
  default = "default"
  description = "VPC network name"
}
variable "machine_type" {
  default = "n1-standard-1"
  description = "Machine type"
}
variable "db_password" {
  description = "Database user password"
}
