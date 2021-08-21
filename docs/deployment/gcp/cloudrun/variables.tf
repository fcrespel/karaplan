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
variable "vpc_connector_ip_range" {
  default     = "10.8.0.0/28"
  description = "Serverless VPC access connector IP range (/28)"
}
variable "min_instances_count" {
  default     = 0
  description = "Minimum number of instances to create"
}
variable "max_instances_count" {
  default     = 5
  description = "Maximum number of instances to create"
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
variable "redis_host" {
  description = "Redis host"
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
