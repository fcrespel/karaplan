variable "name" {
  default = "karaplan-classic"
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
variable "zones" {
  type = list(string)
  description = "GCP zones to use in the region"
}
variable "bucket" {
  description = "GCS bucket name"
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
variable "instances_count" {
  default = 1
  description = "Number of instances to create"
}
variable "machine_type" {
  default = "n1-standard-1"
  description = "Machine type"
}
variable "db_username" {
  default = "karaplan"
  description = "Database user name"
}
variable "db_password" {
  description = "Database user password"
}
variable "db_address" {
  description = "Database address (host:port)"
}
variable "db_name" {
  default = "karaplan"
  description = "Database name"
}
variable "google_oauth_clientid" {
  description = "Google OAuth 2.0 client ID"
}
variable "google_oauth_clientsecret" {
  description = "Google OAuth 2.0 client secret"
}
variable "facebook_oauth_clientid" {
  description = "Facebook OAuth 2.0 client ID"
}
variable "facebook_oauth_clientsecret" {
  description = "Facebook OAuth 2.0 client secret"
}
variable "github_oauth_clientid" {
  description = "GitHub OAuth 2.0 client ID"
}
variable "github_oauth_clientsecret" {
  description = "GitHub OAuth 2.0 client secret"
}
