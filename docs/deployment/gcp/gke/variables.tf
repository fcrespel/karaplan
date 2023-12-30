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
variable "db_instance" {
  description = "Database instance (project_id:region:instance_name)"
}
variable "db_name" {
  description = "Database name"
}
variable "db_username" {
  description = "Database user name"
}
variable "db_password" {
  description = "Database user password"
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
