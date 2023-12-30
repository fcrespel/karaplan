output "gke_cluster_name" {
  value       = google_container_cluster.karaplan-cluster.name
  description = "GKE cluster name"
}
