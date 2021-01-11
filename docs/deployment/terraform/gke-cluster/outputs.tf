output "gke_cluster_name" {
  value       = google_container_cluster.karaplan-cluster.name
  description = "GKE cluster name"
}
output "gke_network_name" {
  value       = google_compute_network.karaplan-network.name
  description = "GKE network name"
}
