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
variable "dns_project_id" {
  default     = ""
  description = "Cloud DNS project ID"
}
variable "dns_zone" {
  default     = ""
  description = "Cloud DNS zone name"
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
